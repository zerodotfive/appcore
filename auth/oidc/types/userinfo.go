package types

import "github.com/golang-jwt/jwt/v5"

type UserInfo struct {
	Login  string   `json:"preferred_username"`
	Name   string   `json:"name"`
	Email  string   `json:"email"`
	Groups []string `json:"groups"`
	jwt.RegisteredClaims
}
