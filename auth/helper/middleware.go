package helper

import (
	"net/http"
	"slices"

	"github.com/danielgtaylor/huma/v2"
	types2 "github.com/zerodotfive/appcore/auth/types"
)

func NewAdminAuthMiddleware(authConfig *types2.AuthConfig, pages *types2.StatusPages) func(ctx huma.Context, next func(huma.Context)) {
	jwt := NewJWT(authConfig.JWTKey)

	return func(ctx huma.Context, next func(huma.Context)) {
		cookie, err := huma.ReadCookie(ctx, "session")
		if err != nil {
			ctx.SetStatus(http.StatusUnauthorized)
			_, _ = ctx.BodyWriter().Write(pages.Unauthorized)
			return
		}

		userInfo, err := jwt.Parse(cookie.Value)

		if err != nil {
			ctx.SetStatus(http.StatusUnauthorized)
			_, _ = ctx.BodyWriter().Write(pages.Unauthorized)
			return
		}

		if !slices.Contains(userInfo.Groups, authConfig.AdminGroup) {
			ctx.SetStatus(http.StatusForbidden)
			_, _ = ctx.BodyWriter().Write(pages.Forbidden)
			return
		}

		next(huma.WithValue(ctx, "userInfo", userInfo))
	}
}

func NewClientAuthMiddleware(authConfig *types2.AuthConfig, pages *types2.StatusPages) func(ctx huma.Context, next func(huma.Context)) {
	jwt := NewJWT(authConfig.JWTKey)

	return func(ctx huma.Context, next func(huma.Context)) {
		cookie, err := huma.ReadCookie(ctx, "session")
		if err != nil {
			ctx.SetStatus(http.StatusUnauthorized)
			_, _ = ctx.BodyWriter().Write(pages.Unauthorized)
			return
		}

		userInfo, err := jwt.Parse(cookie.Value)

		if err != nil {
			ctx.SetStatus(http.StatusUnauthorized)
			_, _ = ctx.BodyWriter().Write(pages.Unauthorized)
			return
		}

		next(huma.WithValue(ctx, "userInfo", userInfo))
	}
}
