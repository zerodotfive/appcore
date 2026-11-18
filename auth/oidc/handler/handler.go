package handler

import (
	"log"
	"net/http"

	"github.com/zerodotfive/appcore/auth/oidc"
)

type Handler struct {
	oauthConfig *oidc.OAuthConfig
	logger      *log.Logger
}

func Register(apiRouter *http.ServeMux, authConfig *oidc.OAuthConfig, logger *log.Logger) {
	h := &Handler{
		oauthConfig: authConfig,
		logger:      logger,
	}

	apiRouter.HandleFunc("GET /auth/login", h.login)
	apiRouter.HandleFunc("GET /auth/logout", h.logout)
	apiRouter.HandleFunc("GET /auth/callback", h.callback)
	apiRouter.HandleFunc("GET /auth/info", h.info)
}
