package types

type AuthConfig struct {
	AuthClientID              string
	AuthClientSecret          string
	AuthRedirectURL           string
	OpenIDConfigurationIssuer string
	JWTKey                    string
	AdminGroup                string
}
