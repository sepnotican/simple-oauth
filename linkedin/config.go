package linkedin

const (
	profileURL = "https://api.linkedin.com/v2/me?projection=(id,firstName,lastName,profilePicture(displayImage~:playableStreams))"
	emailURL   = "https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))"
)

type OAuthExternalConfig struct {
	ClientID     string `yaml:"clientID" json:"clientID" xml:"clientID"`
	ClientSecret string `yaml:"clientSecret" json:"clientSecret" xml:"clientSecret"`
	RedirectURL  string `yaml:"redirectUrl" json:"redirectUrl" xml:"redirectUrl"`
}
