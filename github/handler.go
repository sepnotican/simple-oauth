package github

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
	"golang.org/x/oauth2/github"
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
		Scopes:       []string{"user:email"},
		Endpoint:     github.Endpoint,
	}
	return res
}

func (h *OAuthHandler) OAuthLogin() (oauthState string, url string, err error) {
	b := make([]byte, 16)
	_, err = rand.Read(b)
	oauthState = base64.URLEncoding.EncodeToString(b)
	url = h.oauthConfig.AuthCodeURL(oauthState)
	return
}

type UserData struct {
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

func (u UserData) GetEmail() string {
	return u.Email
}

func (u UserData) GetFirstName() string {
	return u.Name
}

func (u UserData) GetLastName() string {
	return ""
}

func (u UserData) GetAvatarURL() string {
	return u.AvatarURL
}
func (h *OAuthHandler) OAuthCallback(stateCookie, stateForm, code string) (simple_oauth.UserDataSupplier, error) {
	// Check oauthState from Cookie
	if stateForm != stateCookie {
		return nil, errors.New("invalid oauth github state")
	}
	ud, err := h.getUserData(code)
	if err != nil {
		return nil, fmt.Errorf("can't get user data from github, err=%s", err.Error())
	}
	return &ud, nil
}

func (h *OAuthHandler) getUserData(code string) (UserData, error) {
	token, err := h.oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return UserData{}, fmt.Errorf("code is wrong: %s", err.Error())
	}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprint(profileURL, token.AccessToken), nil)
	if err != nil {
		return UserData{}, fmt.Errorf("preparing user profile request failed: %s", err.Error())
	}
	req.Header.Add("Authorization", "token "+token.AccessToken)
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return UserData{}, fmt.Errorf("exec user profile request failed: %s", err.Error())
	}
	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return UserData{}, fmt.Errorf("reading response failed: %s", err.Error())
	}

	var ud UserData
	err = json.Unmarshal(contents, &ud)
	if err != nil {
		return UserData{}, fmt.Errorf("can't parse json response, data=%s", string(contents))
	}

	reqEmail, err := http.NewRequest(http.MethodGet, fmt.Sprint(profileEmailURL, token.AccessToken), nil)
	if err != nil {
		return UserData{}, fmt.Errorf("failed prepaging user info req: %s", err.Error())
	}
	reqEmail.Header.Add("Authorization", "token "+token.AccessToken)
	responseEmail, err := http.DefaultClient.Do(reqEmail)
	if err != nil {
		return UserData{}, fmt.Errorf("failed getting user email info: %s", err.Error())
	}
	defer responseEmail.Body.Close()

	contents, err = ioutil.ReadAll(responseEmail.Body)
	if err != nil {
		return UserData{}, fmt.Errorf("failed read email response: %s", err.Error())
	}
	var opaque []struct {
		Email string `json:"email"`
	}
	err = json.Unmarshal(contents, &opaque)
	if err != nil {
		return UserData{}, fmt.Errorf("can't parse json response, data=%s", string(contents))
	}
	if len(opaque) > 0 {
		ud.Email = opaque[0].Email
	}

	return ud, nil
}
