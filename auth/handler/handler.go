package handler

import (
	"log"
	"net/http"

	"github.com/zerodotfive/appcore/auth/types"
)

type Handler struct {
	authConfig *types.AuthConfig
	logger     *log.Logger
}

func Register(apiRouter *http.ServeMux, authConfig *types.AuthConfig, logger *log.Logger) {
	h := &Handler{
		authConfig: authConfig,
		logger:     logger,
	}

	apiRouter.HandleFunc("GET /auth/login", h.login)
	apiRouter.HandleFunc("GET /auth/logout", h.logout)
	apiRouter.HandleFunc("GET /auth/callback", h.callback)
	apiRouter.HandleFunc("GET /auth/info", h.info)
}
