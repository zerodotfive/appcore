package static

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/zerodotfive/appcore/auth"
)

func NewTokenAuthMiddleware(stageKey string, idpTokenSHAHex string) func(ctx huma.Context, next func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		idpTokenSHA, err := hex.DecodeString(strings.TrimSpace(idpTokenSHAHex))
		if err != nil {
			next(huma.WithValue(ctx, stageKey, http.StatusUnauthorized))
			return
		}

		headerToken := ctx.Header("Authorization")
		if len(headerToken) == 0 {
			next(huma.WithValue(ctx, stageKey, http.StatusUnauthorized))
			return
		}

		if !strings.HasPrefix(headerToken, "Bearer ") {
			next(huma.WithValue(ctx, stageKey, http.StatusUnauthorized))
			return
		}

		token := strings.TrimSpace(strings.TrimPrefix(headerToken, "Bearer"))
		tokenSHA := sha256.Sum256([]byte(token))

		if subtle.ConstantTimeCompare(tokenSHA[:], idpTokenSHA) == 0 {
			next(huma.WithValue(ctx, stageKey, http.StatusUnauthorized))
			return
		}

		userInfo := &auth.UserInfo{Login: "token:static"}
		ctx = huma.WithValue(ctx, stageKey+"+userInfo", userInfo)
		next(huma.WithValue(ctx, stageKey, http.StatusOK))
		return
	}
}
