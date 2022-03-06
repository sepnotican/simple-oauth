package github

const (
	profileURL      = "https://api.github.com/user?access_token="
	profileEmailURL = "https://api.github.com/user/emails?access_token="
)

type OAuthExternalConfig struct {
	ClientID     string `yaml:"clientID" json:"clientID" xml:"clientID"`
	ClientSecret string `yaml:"clientSecret" json:"clientSecret" xml:"clientSecret"`
	RedirectURL  string `yaml:"redirectUrl" json:"redirectUrl" xml:"redirectUrl"`
}
