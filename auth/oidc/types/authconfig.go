package types

type AuthConfig struct {
	AuthClientID              string
	AuthClientSecret          string
	AuthRedirectURL           string
	AuthScopes                []string
	OpenIDConfigurationIssuer string
	JWTKey                    string
	AdminGroup                string
}
