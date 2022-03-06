package facebook

const profileURL = "https://graph.facebook.com/me?fields=id,email,first_name,last_name&access_token="

type OAuthExternalConfig struct {
	ClientID     string `yaml:"clientID" json:"clientID" xml:"clientID"`
	ClientSecret string `yaml:"clientSecret" json:"clientSecret" xml:"clientSecret"`
	RedirectURL  string `yaml:"redirectUrl" json:"redirectUrl" xml:"redirectUrl"`
}
