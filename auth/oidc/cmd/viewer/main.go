package main

import (
	"log"
	"net/http"
	"os"

	"github.com/spf13/viper"
	"github.com/zerodotfive/appcore/auth/oidc"
	"github.com/zerodotfive/appcore/auth/oidc/handler"
)

func main() {
	viper.AutomaticEnv()
	authConfig := oidc.OAuthConfig{
		AuthClientID:              viper.GetString("AUTH_CLIENT_ID"),
		AuthClientSecret:          viper.GetString("AUTH_CLIENT_SECRET"),
		AuthRedirectURL:           viper.GetString("AUTH_REDIRECT_URL"),
		AuthScopes:                viper.GetStringSlice("AUTH_SCOPES"),
		OpenIDConfigurationIssuer: viper.GetString("OPENID_CONFIGURATION_ISSUER"),
		JWTKey:                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
	}

	router := http.NewServeMux()
	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds|log.Lshortfile)

	router.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body><a href=/auth/login>Try</a><p><a href=/auth/info>Info</a></body></html>`))
	})

	handler.Register(router, &authConfig, logger)

	_ = http.ListenAndServe("127.0.0.1:8080", router)
}
