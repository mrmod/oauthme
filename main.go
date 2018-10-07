package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"

	gorilla "github.com/gorilla/mux"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jws"
	calendar "google.golang.org/api/calendar/v3"
	"google.golang.org/api/googleapi"
)

var (
	oauthClient      googleClient
	sessionStore     = map[string]authorizedClient{}
	sessionCalendars = map[string][]calendar.CalendarListEntry{}
)

const (
	serverSecret       = "aRandomishStringForHashing"
	sessionTokenName   = "session_token"
	loginRoute         = "/login"
	logoutRoute        = "/logout"
	homeRoute          = "/home"
	rootRoute          = "/"
	calendarsRoute     = "/calendars"
	calendarRoute      = "/calendars/{calendarID}"
	oauthCallbackRoute = "/oauth2Callback"
	timeFormat         = "2006-01-02T15:04:05Z"
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

// Base64 encoded sessionID
func sessionToken(clientID, subscriber, secret string) string {
	sum := sha256.New().Sum([]byte(clientID + subscriber + secret))
	return base64.StdEncoding.EncodeToString(sum)
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
	redirectTo(w, r, rootRoute)
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

func homeHandler(w http.ResponseWriter, r *http.Request) {
	if _, ok := isAuthorized(r); !ok {
		log.Println("Redirecting unauthorized session to login")
		redirectTo(w, r, loginRoute)
		return
	}
	w.Write([]byte("Welcome home!"))
}

func serverError(w http.ResponseWriter, err error) {
	log.Println("ServerError:", err)
	w.WriteHeader(http.StatusInternalServerError)
}

// GET /calandars
func calendarsListHandler(w http.ResponseWriter, r *http.Request) {
	sessionID, authorized := isAuthorized(r)
	if !authorized {
		redirectTo(w, r, loginRoute)
		return
	}
	session := sessionStore[sessionID]
	log.Println(calendarsRoute, "Restored session", sessionID)
	// Get events
	ctx := context.Background()
	client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(&session.Token))
	service, err := calendar.New(client)
	if err != nil {
		serverError(w, err)
		return
	}
	calendarList, err := service.CalendarList.List().Do()
	if err != nil {
		serverError(w, err)
		return
	}
	for _, entry := range calendarList.Items {
		// Local/resident datastore
		sessionCalendars[sessionID] = append(sessionCalendars[sessionID], *entry)
	}
	// TODO: Can marshall directly
	usersCalendars, _ := json.Marshal(sessionCalendars[sessionID])
	w.Header().Set("Content-Type", "application/json")
	w.Write(usersCalendars)

}
func calendarListEntryHandler(w http.ResponseWriter, r *http.Request) {
	sessionID, authorized := isAuthorized(r)
	if !authorized {
		redirectTo(w, r, loginRoute)
		return
	}
	session := sessionStore[sessionID]
	ctx := context.Background()
	client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(&session.Token))
	service, err := calendar.New(client)
	if err != nil {
		serverError(w, err)
		return
	}
	calendarID := gorilla.Vars(r)["calendarID"]
	log.Printf("Finding events for %s", calendarID)
	timeMax := time.Now().Add(time.Hour * 24).Format(timeFormat)
	timeMin := time.Now().Format(timeFormat)
	events, err := service.Events.List(calendarID).TimeMax(timeMax).TimeMin(timeMin).Do()
	if err != nil {
		switch t := err.(type) {
		case *googleapi.Error:
			w.WriteHeader(t.Code)
			return
		default:
			serverError(w, err)
			return
		}
	}

	setContentTypeJSON(w)
	setCORSHeaders(w)
	eventsJSON, _ := events.MarshalJSON()
	w.Write(eventsJSON)
}
func loginHandler(w http.ResponseWriter, r *http.Request) {
	index, _ := ioutil.ReadFile("public/index.html")
	setCORSHeaders(w)
	_, _ = w.Write(index)
}
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:    sessionTokenName,
		Expires: time.Unix(0, 0),
	})
	redirectTo(w, r, loginRoute)
}
func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
func isAuthorized(r *http.Request) (sessionID string, ok bool) {
	c, err := r.Cookie(sessionTokenName)
	if err != nil {
		return
	}
	if err == nil {
		sessionID = c.Value
		ok = true
	}
	if session, sessionOK := sessionStore[sessionID]; !sessionOK {
		ok = false
	} else {
		if !session.Valid() {
			ok = false
		}
	}
	return
}

func redirectTo(w http.ResponseWriter, r *http.Request, path string) {
	// setCORSHeaders(w)
	http.Redirect(w, r, path, http.StatusTemporaryRedirect)
}
func setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
	w.Header().Set("Access-Control-Max-Age", "3600")
}
func setContentTypeJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
}
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setCORSHeaders(w)
		next.ServeHTTP(w, r)
	})
}

// TODO: Not fully generalized. Only handls the calendarsRoute
func main() {
	r := gorilla.NewRouter()
	// Calendars
	r.HandleFunc(calendarsRoute, calendarsListHandler)
	calendarsRouter := r.PathPrefix(calendarsRoute).Subrouter()
	calendarsRouter.HandleFunc("/", calendarsListHandler)
	calendarsRouter.HandleFunc("/{calendarID}", calendarListEntryHandler)

	r.HandleFunc(oauthCallbackRoute, oauthHandler)
	r.HandleFunc(homeRoute, homeHandler)
	r.HandleFunc(loginRoute, loginHandler)
	r.HandleFunc(logoutRoute, logoutHandler)
	r.HandleFunc("/", homeHandler)

	r.Use(logMiddleware)
	r.Use(corsMiddleware)

	http.Handle("/", r)
	http.ListenAndServe(":8080", nil)
}
