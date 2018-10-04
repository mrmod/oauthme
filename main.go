package main

import (
	"crypto/sha256"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jws"
	// calendar "google.golang.org/api/calendar/v3"
)

var (
	oauthClient  googleClient
	sessionStore = map[string]authorizedClient{}
)

const (
	serverSecret       = "aRandomishStringForHashing"
	sessionTokenName   = "session_token"
	loginRoute         = "/login"
	homeRoute          = "/home"
	eventsRoute        = "/events"
	oauthCallbackRoute = "/oauth2Callback"
)

type token int

type googleSecret struct {
	Web googleClient `json:"web"`
}

// Unauthorized Google client (the server's agent)
type googleClient struct {
	ID           string   `json:"client_id"`
	Secret       string   `json:"client_secret"`
	RedirectUris []string `json:"redirect_uris"`
}

// Authorized client
type authorizedClient struct {
	oauth2.Token        // Allows a .Valid() validation call
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token"`
}

// tokenRequest Values for getting an authorization code or oauth access
// and refresh token
func (c googleClient) tokenRequest(callbackCode string) url.Values {
	return url.Values{
		"client_id":     {c.ID},
		"client_secret": {c.Secret},
		"redirect_uri":  {c.RedirectUris[0]},
		"grant_type":    {"authorization_code"},
		"code":          {callbackCode},
	}
}

func init() {
	secrets, _ := ioutil.ReadFile("secret.json")
	secret := googleSecret{}
	err := json.Unmarshal(secrets, &secret)
	if err != nil {
		panic(err)
	}
	oauthClient = secret.Web
	log.Printf("Initialized GoogleClient %s", oauthClient.ID)
}

func exchangeForToken(authCode string) (client authorizedClient, err error) {
	google := "https://www.googleapis.com/oauth2/v4/token"
	response, _ := http.PostForm(google, oauthClient.tokenRequest(authCode))

	responseBody, _ := ioutil.ReadAll(response.Body)
	err = json.Unmarshal(responseBody, &client)
	return client, err
}

func sessionToken(clientID, subscriber, secret string) string {
	return string(sha256.New().Sum([]byte(clientID + subscriber + secret)))
}

func setSession(apiClient authorizedClient, w http.ResponseWriter, r *http.Request) {
	claimSet, err := jws.Decode(apiClient.IDToken)
	if err != nil {
		log.Println("Unable to decode ID token claim set", err)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	sessionID := sessionToken(oauthClient.ID, claimSet.Sub, serverSecret)
	http.SetCookie(w, &http.Cookie{
		Name:    sessionTokenName,
		Value:   sessionID,
		Expires: time.Now().Add(time.Duration(apiClient.ExpiresIn-1) * time.Second),
	})
	sessionStore[sessionID] = apiClient
	// Redirect to the authorized portion of the site
	http.Redirect(w, r, "/home", http.StatusTemporaryRedirect)
}

// Handle the OAuth callback triggered by a Login request
func oauthHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		log.Println("Unparseable form", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if authCode := r.Form.Get("code"); len(authCode) > 0 {
		apiClient, err := exchangeForToken(authCode)
		if err != nil {
			log.Println("Error exchanging auth code", err)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		setSession(apiClient, w, r)
		return
	}
	w.WriteHeader(http.StatusForbidden)
}
func isAuthorized(r *http.Request) (sessionID string, ok bool) {
	c, err := r.Cookie(sessionTokenName)
	if err == nil {
		sessionID = c.Value
		ok = true
	}
	return
}

func redirectTo(w http.ResponseWriter, r *http.Request, path string) {
	http.Redirect(w, r, path, http.StatusTemporaryRedirect)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	_, authorized := isAuthorized(r)
	if !authorized {
		redirectTo(w, r, loginRoute)
		return
	}
	w.Write([]byte("Welcome home!"))
}

func eventsHandler(w http.ResponseWriter, r *http.Request) {
	sessionID, authorized := isAuthorized(r)
	if !authorized {
		redirectTo(w, r, loginRoute)
		return
	}
	session := sessionStore[sessionID]
	_ = session
	// Get events
	// ctx := context.Background()
	// oauth2Client := oauth2.NewClient(ctx, session)
	// service, err := calendar.New()
}
func loginHandler(w http.ResponseWriter, r *http.Request) {
	_, authorized := isAuthorized(r)
	if authorized {
		redirectTo(w, r, homeRoute)
	}
	index, _ := ioutil.ReadFile("public/index.html")
	_, _ = w.Write(index)
}

func main() {
	http.HandleFunc(oauthCallbackRoute, oauthHandler)
	http.HandleFunc(homeRoute, homeHandler)
	http.HandleFunc(eventsRoute, eventsHandler)
	http.HandleFunc(loginRoute, loginHandler)
	http.ListenAndServe(":8080", nil)
}
