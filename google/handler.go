package google

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	simple_oauth "github.com/sepnotican/simple-oauth"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type OAuthHandler struct {
	externalConfig *OAuthExternalConfig
	oauthConfig    *oauth2.Config
}

func New(c *OAuthExternalConfig) *OAuthHandler {
	res := &OAuthHandler{externalConfig: c}
	res.oauthConfig = &oauth2.Config{
		RedirectURL:  c.RedirectURL,
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
		Endpoint:     google.Endpoint,
	}
	return res
}

func (h *OAuthHandler) OAuthLogin() (oauthState string, url string, err error) {
	// Create oauthState cookie
	b := make([]byte, 16)
	_, err = rand.Read(b)
	oauthState = base64.URLEncoding.EncodeToString(b)
	url = h.oauthConfig.AuthCodeURL(oauthState)
	return
}

type UserData struct {
	Email      string `json:"email"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
	Picture    string `json:"picture"`
}

func (u UserData) GetEmail() string {
	return u.Email
}

func (u UserData) GetFirstName() string {
	return u.GivenName
}

func (u UserData) GetLastName() string {
	return u.FamilyName
}

func (u UserData) GetAvatarURL() string {
	return u.Picture
}

func (h *OAuthHandler) OAuthCallback(stateCookie, stateResponse, code string) (simple_oauth.UserDataSupplier, error) {
	// Check oauthState from Cookie
	if stateResponse != stateCookie {
		return nil, errors.New("invalid oauth google state")
	}

	data, err := h.getUserData(code)
	if err != nil {
		return nil, fmt.Errorf("can't get user data from google, err=%s", err.Error())
	}
	var ud = UserData{}
	err = json.Unmarshal(data, &ud)
	if err != nil {
		return nil, fmt.Errorf("can't parse json response, data=%s", string(data))
	}
	return &ud, nil
}

func (h *OAuthHandler) getUserData(code string) ([]byte, error) {
	token, err := h.oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return nil, fmt.Errorf("code %s is wrong: %s", code, err.Error())
	}
	response, err := http.Get(fmt.Sprint(profileURL, token.AccessToken))
	if err != nil {
		return nil, fmt.Errorf("failed: get user info: %s", err.Error())
	}
	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed read response: %s", err.Error())
	}
	return contents, nil
}
