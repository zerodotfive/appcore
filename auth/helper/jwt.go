package helper

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/zerodotfive/appcore/auth/types"
)

type JWT struct {
	key []byte
}

func NewJWT(key string) *JWT {
	return &JWT{
		key: []byte(key),
	}
}

func (j *JWT) Issue(u *types.UserInfo) (string, error) {
	c := types.UserInfo{
		Login: u.Login, Name: u.Name, Email: u.Email, Groups: u.Groups,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   u.Login,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	return jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(j.key)
}

func (j *JWT) Parse(raw string) (*types.UserInfo, error) {
	var c types.UserInfo
	_, err := jwt.ParseWithClaims(raw, &c,
		func(*jwt.Token) (any, error) { return j.key, nil },
		jwt.WithValidMethods([]string{"HS256"}), // защита от подмены алгоритма
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, err
	}

	if len(c.Login) == 0 {
		return nil, errors.New("invalid token")
	}

	return &c, nil
}
