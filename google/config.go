package google

const profileURL = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="

type OAuthExternalConfig struct {
	ClientID     string `yaml:"clientID" json:"clientID" xml:"clientID"`
	ClientSecret string `yaml:"clientSecret" json:"clientSecret" xml:"clientSecret"`
	RedirectURL  string `yaml:"redirectUrl" json:"redirectUrl" xml:"redirectUrl"`
}
