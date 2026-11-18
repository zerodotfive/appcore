package auth

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

func NewAuthSolverMiddleware(pages *StatusPages, stages []string) func(ctx huma.Context, next func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		fail := http.StatusUnauthorized

		for _, stage := range stages {
			stageStatus, ok := ctx.Context().Value(stage).(int)
			if !ok {
				ctx.SetStatus(http.StatusInternalServerError)
				return
			}

			if stageStatus == http.StatusOK {
				stageUserInfo, ok := ctx.Context().Value(stage + "+userInfo").(*UserInfo)
				if !ok {
					ctx.SetStatus(http.StatusInternalServerError)
					return
				}

				next(huma.WithValue(ctx, "userInfo", stageUserInfo))
				return
			}

			if stageStatus != http.StatusUnauthorized {
				fail = stageStatus
			}
		}

		ctx.SetStatus(fail)
		_, _ = ctx.BodyWriter().Write(pages.getByStatus(fail))
		return
	}
}
