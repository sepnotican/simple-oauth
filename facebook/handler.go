package facebook

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	simple_oauth "github.com/sepnotican/simple-oauth"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
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
		Scopes:       []string{"email", "public_profile"},
		Endpoint:     facebook.Endpoint,
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

type UserDataContainer struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

func (u UserDataContainer) GetEmail() string {
	return u.Email
}

func (u UserDataContainer) GetFirstName() string {
	return u.FirstName
}

func (u UserDataContainer) GetLastName() string {
	return u.LastName
}
func (u UserDataContainer) GetAvatarURL() string {
	return fmt.Sprintf("https://graph.facebook.com/%s/picture?type=large&width=72&height=72", u.ID)
}

func (h *OAuthHandler) OAuthCallback(stateCookie, stateForm, code string) (simple_oauth.UserDataSupplier, error) {
	if stateForm != stateCookie {
		return nil, errors.New("invalid oauth state")
	}

	data, err := h.getUserDataFromFacebook(code)
	if err != nil {
		return nil, errors.New("can't get user data from facebook")
	}

	var ud = UserDataContainer{}
	err = json.Unmarshal(data, &ud)
	if err != nil {
		return nil, fmt.Errorf("can't parse json response, data=%s", string(data))
	}
	return &ud, nil
}

func (h *OAuthHandler) getUserDataFromFacebook(code string) ([]byte, error) {
	token, err := h.oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong: %s", err.Error())
	}

	resp, err := http.Get(profileURL + url.QueryEscape(token.AccessToken))

	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	defer resp.Body.Close()
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed read resp: %s", err.Error())
	}
	return content, nil
}
