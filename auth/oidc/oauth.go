package oidc

import (
	"context"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func GetOAuth(ctx context.Context, config *OAuthConfig) (*oidc.Provider, *oauth2.Config, error) {
	provider, err := oidc.NewProvider(ctx, config.OpenIDConfigurationIssuer)
	if err != nil {
		return nil, nil, err
	}

	return provider, &oauth2.Config{
		ClientID:     config.AuthClientID,
		ClientSecret: config.AuthClientSecret,
		RedirectURL:  config.AuthRedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       config.AuthScopes,
	}, nil
}

func GetVerifierConfig(config *OAuthConfig) *oidc.Config {
	return &oidc.Config{
		ClientID: config.AuthClientID,
	}
}
