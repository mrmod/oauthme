package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
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
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
}

// tokenRequest Values for getting an authorization code or oauth access
// and refresh token
func (c googleClient) tokenRequest(callbackCode string) url.Values {
	return url.Values{
		"client_id":     {c.ID},
		"client_secret": {c.Secret},
		"redirect_uris": {c.RedirectUris[0]},
		"grant_type":    {"authorization_code"},
		"code":          {callbackCode},
	}
}

var oauthClient googleClient

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

func exchangeForToken(authCode string) (authorizedClient, error) {
	google := "https://www.googleapis.com/oauth2/v4/token"
	response, _ := http.PostForm(
		google,
		oauthClient.tokenRequest(authCode),
	)

	client := authorizedClient{}
	responseBody, _ := ioutil.ReadAll(response.Body)
	err := json.Unmarshal(responseBody, &client)
	return client, err
}

func oauthRedirect(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling oauth redirect")
	if err := r.ParseForm(); err != nil {
		log.Println("Unparseable form", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	log.Printf("Form %#v", r.Form)
	authCode := r.Form.Get("code")
	log.Println("AuthCode", authCode)
	// if apiClient, err := exchangeForToken(authCode); err != nil {
	// 	w.WriteHeader(http.StatusForbidden)
	// 	return
	// } else {
	// 	log.Printf("Authorized apiClient %#v", apiClient)
	// }

	// Finally, redirect to the authorized portion of the site
	w.WriteHeader(http.StatusOK)
}

func main() {
	http.HandleFunc("/oauth2Callback", oauthRedirect)
	http.ListenAndServe(":8080", nil)
}
