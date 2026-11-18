package auth

import (
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

type UserInfo struct {
	Login  string   `json:"preferred_username"`
	Name   string   `json:"name"`
	Email  string   `json:"email"`
	Groups []string `json:"groups"`
	jwt.RegisteredClaims
}

type StatusPages struct {
	Unauthorized []byte
	Forbidden    []byte
}

func (p *StatusPages) getByStatus(status int) []byte {
	switch status {
	case http.StatusUnauthorized:
		return p.Unauthorized
	case http.StatusForbidden:
		return p.Forbidden
	default:
		return []byte(fmt.Sprintf("%d", status))
	}
}
