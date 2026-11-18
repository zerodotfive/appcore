package oidc

type OAuthConfig struct {
	AuthClientID              string
	AuthClientSecret          string
	AuthRedirectURL           string
	AuthScopes                []string
	OpenIDConfigurationIssuer string
	JWTKey                    string
}
