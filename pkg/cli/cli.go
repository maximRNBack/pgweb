package cli

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"

	"github.com/gin-gonic/gin"
	"github.com/jessevdk/go-flags"

	"github.com/sosedoff/pgweb/pkg/api"
	"github.com/sosedoff/pgweb/pkg/bookmarks"
	"github.com/sosedoff/pgweb/pkg/client"
	"github.com/sosedoff/pgweb/pkg/command"
	"github.com/sosedoff/pgweb/pkg/connection"
	"github.com/sosedoff/pgweb/pkg/shared"
	"github.com/sosedoff/pgweb/pkg/util"
	"github.com/gin-contrib/sessions"
	"net/http"
	"io/ioutil"
	"encoding/json"
	"github.com/maximRNBack/gin-oidc"
	"bytes"
	"log"
	"net/url"
	"strings"
	"errors"
	"golang.org/x/oauth2/clientcredentials"
)

var options command.Options

func exitWithMessage(message string) {
	fmt.Println("Error:", message)
	os.Exit(1)
}

func initClientUsingBookmark(bookmarkPath, bookmarkName string) (*client.Client, error) {
	bookmark, err := bookmarks.GetBookmark(bookmarkPath, bookmarkName)
	if err != nil {
		return nil, err
	}

	opt := bookmark.ConvertToOptions()
	var connStr string

	if opt.Url != "" { // if the bookmark has url set, use it
		connStr = opt.Url
	} else {
		connStr, err = connection.BuildString(opt)
		if err != nil {
			return nil, fmt.Errorf("error building connection string: %v", err)
		}
	}

	var ssh *shared.SSHInfo
	if !bookmark.SSHInfoIsEmpty() {
		ssh = &bookmark.Ssh
	}

	return client.NewFromUrl(connStr, ssh)
}

func initClient() {
	if connection.IsBlank(command.Opts) && options.Bookmark == "" {
		return
	}

	var cl *client.Client
	var err error

	if options.Bookmark != "" {
		cl, err = initClientUsingBookmark(bookmarks.Path(options.BookmarksDir), options.Bookmark)
	} else {
		cl, err = client.New()
	}

	if err != nil {
		exitWithMessage(err.Error())
	}

	if command.Opts.Debug {
		fmt.Println("Server connection string:", cl.ConnectionString)
	}

	fmt.Println("Connecting to server...")
	err = cl.Test()
	if err != nil {
		exitWithMessage(err.Error())
	}

	fmt.Println("Checking database objects...")
	_, err = cl.Objects()
	if err != nil {
		exitWithMessage(err.Error())
	}

	api.DbClient = cl
}

func initOptions() {
	err := command.ParseOptions()
	if err != nil {
		switch err.(type) {
		case *flags.Error:
			// no need to print error, flags package already does that
		default:
			fmt.Println(err.Error())
		}
		os.Exit(1)
	}

	options = command.Opts

	if options.Version {
		printVersion()
		os.Exit(0)
	}

	if options.ReadOnly {
		msg := `------------------------------------------------------
SECURITY WARNING: You are running pgweb in read-only mode.
This mode is designed for environments where users could potentially delete / change data.
For proper read-only access please follow postgresql role management documentation.
------------------------------------------------------`
		fmt.Println(msg)
	}

	printVersion()
}

func printVersion() {
	str := fmt.Sprintf("Pgweb v%s", command.VERSION)
	if command.GitCommit != "" {
		str += fmt.Sprintf(" (git: %s)", command.GitCommit)
	}

	fmt.Println(str)
}

func redirectToErrorPage(c *gin.Context, errorEndpoint url.URL, message string) {
	c.Error(errors.New(message))
	errorEndpoint.RawQuery = (url.Values{"err": []string{message}}).Encode()
	c.Redirect(http.StatusFound, errorEndpoint.String())
}
func initServerSessions(router *gin.Engine) {
	store := sessions.NewCookieStore([]byte(gin_oidc.RandomString(32)))
	router.Use(sessions.Sessions("ServerSessions", store))
	// read & parse secrets from file
	secrets := readSecrets()
	issuer, err := url.Parse(secrets.UsersOidcConfig.Issuer)
	if err != nil {
		log.Fatal("Failed to parse 'issuer'")
	}
	pgwebUrl, err := url.Parse(secrets.PgwebUrl)
	if err != nil {
		log.Fatal("Failed to parse 'pgwebUrl'")
	}
	postLogoutUrl, err := url.Parse(secrets.LogoutRedirectUrl)
	if err != nil {
		log.Fatal("Failed to parse 'logoutRedirectUrl'")
	}
	errorEndpoint, err := url.Parse(secrets.ErrorEndpoint)
	if err != nil {
		log.Fatal("Failed to parse 'errorEndpoint'")
	}
	// OIDC middleware params
	initParams := gin_oidc.InitParams{
		Router:       router,
		ClientId:     secrets.UsersOidcConfig.ClientId,
		ClientSecret: secrets.UsersOidcConfig.ClientSecret,
		Issuer:       *issuer,
		ClientUrl:    *pgwebUrl,
		Scopes:       secrets.UsersOidcConfig.Scopes,
		ErrorHandler: func(c *gin.Context) {
			//gin_oidc pushes a new error before any "ErrorHandler" invocation
			message := c.Errors.Last().Error()
			//redirect to ErrorEndpoint with error message
			redirectToErrorPage(c, *errorEndpoint, message)
			//when "ErrorHandler" ends "c.Abort()" is invoked - no further handlers will be invoked
		},
		PostLogoutUrl: *postLogoutUrl, // TODO maybe set to '/disconnect'?
	}
	// OIDC authentication middleware
	router.Use(gin_oidc.Init(initParams))

	// PGWEB authorization assertion middleware
	router.Use(func(c *gin.Context) {
		if _, ok := sessions.Default(c).Get("session_id").(string);
			!ok && !strings.HasPrefix(c.Request.URL.Path, "/authorize") {
			//this middleware is after OIDC middleware, so it means user is authenticated
			// but not authorized, so he didn't access the '/authorize/:id' endpoint or the access failed
			redirectToErrorPage(c, *errorEndpoint, "didn't access '/authorize/:id' endpoint")
			c.Abort()
		}
	})

	//pgweb's authorization endpoint
	router.GET("/authorize/:id", func(c *gin.Context) {
		//at this point the user must be authenticated - now we authorize the access and connect him
		serverSession := sessions.Default(c)

		claimsJson, ok := (serverSession.Get("oidcClaims")).(string)
		if !ok {
			redirectToErrorPage(c, *errorEndpoint, "oidc claims not set")
			return
		}
		var claims map[string]interface{}
		if err := json.Unmarshal([]byte(claimsJson), &claims); err != nil {
			redirectToErrorPage(c, *errorEndpoint, "failed to parse oidc claims")
			return
		}

		id := c.Param("id")
		if id == "" {
			redirectToErrorPage(c, *errorEndpoint, "id query parameter not set")
			return
		}
		requestBody := map[string]interface{}{"oidcClaims": claims, "id": id}
		jsonStr, err := json.Marshal(requestBody)
		if err != nil {
			redirectToErrorPage(c, *errorEndpoint, "failed to encode url connection request")
			return
		}
		conf := clientcredentials.Config{
			ClientID: secrets.CredentialsOidcConfig.ClientId,
			ClientSecret: secrets.CredentialsOidcConfig.ClientSecret,
			TokenURL: secrets.CredentialsOidcConfig.Issuer + "/protocol/openid-connect/token",
			Scopes: secrets.CredentialsOidcConfig.Scopes,
		}
		token, err := conf.Token(c.Request.Context())
		if err != nil{
			panic(err)
		}
		req, err := http.NewRequest("POST", secrets.GetConnUrlEndpoint, bytes.NewBuffer(jsonStr))
		req.Header.Set("Content-Type", "application/json")
		token.SetAuthHeader(req)
		httpClient := &http.Client{}

		resp, err := httpClient.Do(req)
		if err != nil {
			redirectToErrorPage(c, *errorEndpoint, "url connection request failed")
			return
		}
		//defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			redirectToErrorPage(c, *errorEndpoint, "url connection request error (resp.StatusCode != 200)")
			return
		}

		body, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			redirectToErrorPage(c, *errorEndpoint, "failed to read url connection from response")
			return
		}

		sessionId := gin_oidc.RandomString(32)
		serverSession.Set("session_id", sessionId)
		err = serverSession.Save()
		if err != nil {
			redirectToErrorPage(c, *errorEndpoint, "failed to save session. error:"+err.Error())
			return
		}

		cl, err := client.NewFromUrl(string(body), nil)
		if err != nil {
			redirectToErrorPage(c, *errorEndpoint, "failed to create pgweb client: "+err.Error())
			return
		}

		_, err = cl.Info()
		if err == nil {
			err = api.SetClient(c, cl)
		}
		if err != nil {
			redirectToErrorPage(c, *errorEndpoint, "failed to init pgweb client: "+err.Error())
			cl.Close()
			return
		}
		c.Redirect(http.StatusFound, fmt.Sprintf("/%s?session=%s", command.Opts.Prefix, sessionId))
	})
}

type oidcConf struct {
	ClientId     string   `json:"clientId"`
	ClientSecret string   `json:"clientSecret"`
	Issuer       string   `json:"issuer"`
	Scopes       []string `json:"scopes"`
}

type secrets struct {
	UsersOidcConfig       oidcConf `json:"usersOidcConfig"`
	CredentialsOidcConfig oidcConf `json:"credentialsOidcConfig"`
	PgwebUrl              string   `json:"pgwebUrl"`
	LogoutRedirectUrl     string   `json:"logoutRedirectUrl"`
	GetConnUrlEndpoint    string   `json:"getConnUrlEndpoint"`
	ErrorEndpoint         string   `json:"errorEndpoint"`
}

func readSecrets() secrets {
	raw, err := ioutil.ReadFile("./secrets.json")
	if err != nil {
		fmt.Println("failed to read secrets")
		fmt.Println(err.Error())
		os.Exit(1)
	}
	var s secrets
	json.Unmarshal(raw, &s)
	return s
}

func startServer() {
	router := gin.Default()

	if command.Opts.ServerSessions {
		initServerSessions(router)
	}
	// Enable HTTP basic authentication only if both user and password are set
	if options.AuthUser != "" && options.AuthPass != "" {
		auth := map[string]string{options.AuthUser: options.AuthPass}
		router.Use(gin.BasicAuth(auth))
	}

	api.SetupRoutes(router)

	fmt.Println("Starting server...")
	go func() {
		err := router.Run(fmt.Sprintf("%v:%v", options.HttpHost, options.HttpPort))
		if err != nil {
			fmt.Println("Cant start server:", err)
			os.Exit(1)
		}
	}()
}

func handleSignals() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill)
	<-c
}

func openPage() {
	url := fmt.Sprintf("http://%v:%v/%s", options.HttpHost, options.HttpPort, options.Prefix)
	fmt.Println("To view database open", url, "in browser")

	if options.SkipOpen {
		return
	}

	_, err := exec.Command("which", "open").Output()
	if err != nil {
		return
	}

	exec.Command("open", url).Output()
}

func Run() {
	initOptions()
	initClient()

	if api.DbClient != nil {
		defer api.DbClient.Close()
	}

	if !options.Debug {
		gin.SetMode("release")
	}

	// Print memory usage every 30 seconds with debug flag
	if options.Debug {
		util.StartProfiler()
	}

	startServer()
	openPage()
	handleSignals()
}
