package oidc

import (
	"net/http"
	"slices"

	"github.com/danielgtaylor/huma/v2"
	"github.com/zerodotfive/appcore/auth"
)

func NewOIDCAuthMiddleware(stageKey string, authConfig *OAuthConfig, restrictGroups []string) func(ctx huma.Context, next func(huma.Context)) {
	jwt := auth.NewJWT(authConfig.JWTKey)

	return func(ctx huma.Context, next func(huma.Context)) {
		cookie, err := huma.ReadCookie(ctx, "session")
		if err != nil {
			next(huma.WithValue(ctx, stageKey, http.StatusUnauthorized))
			return
		}

		userInfo, err := jwt.Parse(cookie.Value)

		if err != nil {
			next(huma.WithValue(ctx, stageKey, http.StatusUnauthorized))
			return
		}

		if len(restrictGroups) == 0 {
			ctx = huma.WithValue(ctx, stageKey+"+userInfo", userInfo)

			next(huma.WithValue(ctx, stageKey, http.StatusOK))
			return
		}

		for _, group := range restrictGroups {
			if slices.Contains(userInfo.Groups, group) {
				ctx = huma.WithValue(ctx, stageKey+"+userInfo", userInfo)

				next(huma.WithValue(ctx, stageKey, http.StatusOK))
				return
			}
		}

		next(huma.WithValue(ctx, stageKey, http.StatusForbidden))
	}
}
