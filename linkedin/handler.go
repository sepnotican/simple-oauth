package linkedin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"

	simple_oauth "github.com/sepnotican/simple-oauth"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/linkedin"
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
		Scopes:       []string{"r_liteprofile", "r_emailaddress"},
		Endpoint:     linkedin.Endpoint,
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
	Email     string
	FirstName string
	LastName  string
	AvatarUrl string
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
	return u.AvatarUrl
}

func (h *OAuthHandler) OAuthCallback(stateCookie, stateForm, code string) (simple_oauth.UserDataSupplier, error) {
	// Check oauthState from Cookie
	if stateForm != stateCookie {
		return nil, errors.New("invalid oauth state")
	}
	token, err := h.oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong: %s", err.Error())
	}
	firstName, lastName, urlAvatar, err := h.getUserNameAvatarFromLinkedIn(token.AccessToken)
	if err != nil {
		return nil, errors.New("can't get user data from linked in")
	}
	email, err := h.getEmailFromLinkedIn(token.AccessToken)
	if err != nil {
		return nil, errors.New("can't get user email from linked in")
	}
	var ud = UserDataContainer{
		FirstName: firstName,
		LastName:  lastName,
		Email:     email,
		AvatarUrl: urlAvatar,
	}
	return &ud, nil
}

func (h *OAuthHandler) getUserNameAvatarFromLinkedIn(accessToken string) (string, string, string, error) {
	req, err := http.NewRequest("GET", profileURL, nil)
	if err != nil {
		return "", "", "", fmt.Errorf("failed getting user info: %s", err.Error())
	}
	req.Header.Add("Authorization", "Bearer "+accessToken)
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", "", fmt.Errorf("failed doing request: %s", err.Error())
	}
	defer response.Body.Close()
	content, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", "", "", fmt.Errorf("failed read response: %s", err.Error())
	}
	logrus.Info("recieved user data from LINKEDIN(me)=", string(content))
	var opaque = struct {
		FirstName struct {
			PreferredLocale struct {
				Country  string `json:"country"`
				Language string `json:"language"`
			} `json:"preferredLocale"`
			Localized map[string]string `json:"localized"`
		} `json:"firstName"`
		LastName struct {
			PreferredLocale struct {
				Country  string `json:"country"`
				Language string `json:"language"`
			} `json:"preferredLocale"`
			Localized map[string]string `json:"localized"`
		} `json:"lastName"`
		ProfilePicture struct {
			DisplayImage struct {
				Elements []struct {
					Data struct {
						MediaData struct {
							StorageSize struct {
								Height int `json:"height"`
							} `json:"storageSize"`
						} `json:"com.linkedin.digitalmedia.mediaartifact.StillImage"`
					} `json:"data"`
					Identifiers []struct {
						Identifier     string `json:"identifier"`
						IdentifierType string `json:"identifierType"`
					} `json:"identifiers"`
				} `json:"elements"`
			} `json:"displayImage~"`
		} `json:"profilePicture"`
	}{}
	if err := json.Unmarshal(content, &opaque); err != nil {
		return "", "", "", err
	}
	langTag := fmt.Sprint(opaque.FirstName.PreferredLocale.Language, "_", opaque.FirstName.PreferredLocale.Country)
	firstName, hasFn := opaque.FirstName.Localized[langTag]
	langTag = fmt.Sprint(opaque.LastName.PreferredLocale.Language, "_", opaque.LastName.PreferredLocale.Country)
	lastName, hasLn := opaque.LastName.Localized[langTag]
	if !hasFn && !hasLn {
		return "", "", "", fmt.Errorf("can't get name from linked in, contentd=%s", content)
	}
	var urlAvatar string

	if len(opaque.ProfilePicture.DisplayImage.Elements) > 0 {
		sort.Slice(opaque.ProfilePicture.DisplayImage.Elements, func(i, j int) bool {
			// move max size to top
			return opaque.ProfilePicture.DisplayImage.Elements[i].Data.MediaData.StorageSize.Height >
				opaque.ProfilePicture.DisplayImage.Elements[j].Data.MediaData.StorageSize.Height
		})
		// find EXTERNAL_URL type
		for _, idf := range opaque.ProfilePicture.DisplayImage.Elements[0].Identifiers {
			if idf.IdentifierType == "EXTERNAL_URL" {
				urlAvatar = idf.Identifier
				break
			}
		}
	}

	return firstName, lastName, urlAvatar, nil
}

func (h *OAuthHandler) getEmailFromLinkedIn(accessToken string) (string, error) {
	req, err := http.NewRequest("GET", emailURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed getting user email: %s", err.Error())
	}
	req.Header.Add("Authorization", "Bearer "+accessToken)
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed getting user info: %s", err.Error())
	}
	defer response.Body.Close()
	content, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("failed read response: %s", err.Error())
	}
	var opaque = struct {
		Elements []struct {
			Handle struct {
				Email string `json:"emailAddress"`
			} `json:"handle~"`
		} `json:"elements"`
	}{}
	if err := json.Unmarshal(content, &opaque); err != nil {
		return "", fmt.Errorf("failed unmarshall response: %s", err.Error())
	}
	if len(opaque.Elements) < 1 {
		return "", fmt.Errorf("unmarshalled response does not contains elements: %+v", opaque)
	}
	return opaque.Elements[0].Handle.Email, nil
}
