package handler

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/zerodotfive/appcore/auth"
	"github.com/zerodotfive/appcore/auth/oidc"
)

type ModelSessionInfoGETResponseBody struct {
	Status   bool           `json:"status"`
	UserInfo *auth.UserInfo `json:"user_info"`
}

func safeReturn(referer string, currentHost string) string {
	if len(referer) == 0 {
		return "/"
	}

	rp, err := url.Parse(referer)
	if err != nil || rp == nil {
		return "/"
	}

	if rp.Host != currentHost {
		return "/"
	}

	return rp.String()
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	_, oauth, err := oidc.GetOAuth(r.Context(), h.oauthConfig)
	if err != nil {
		h.logger.Printf("login: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	b := make([]byte, 32)
	_, err = rand.Read(b)
	if err != nil {
		h.logger.Printf("rand: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	state := base64.RawURLEncoding.EncodeToString(b)

	returnURL := safeReturn(r.Header.Get("Referer"), r.Host)

	http.SetCookie(w, &http.Cookie{
		Name:     "state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "return",
		Value:    returnURL,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	http.Redirect(w, r, oauth.AuthCodeURL(state), http.StatusFound)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "state",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	returnURL := safeReturn(r.Header.Get("Referer"), r.Host)

	http.Redirect(w, r, returnURL, http.StatusFound)
}

func (h *Handler) callback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	returnCookie, err := r.Cookie("return")
	if err != nil {
		h.logger.Printf("callback: %s", err.Error())
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	stateCookie, err := r.Cookie("state")
	if err != nil {
		h.logger.Printf("callback: %s", err.Error())
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	if code == "" || state == "" {
		h.logger.Printf("callback: invalid code/state")
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	provider, oauth, err := oidc.GetOAuth(r.Context(), h.oauthConfig)
	if err != nil {
		h.logger.Printf("callback: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	if state != stateCookie.Value {
		h.logger.Printf("callback: invalid state")
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	token, err := oauth.Exchange(r.Context(), code)
	if err != nil {
		h.logger.Printf("callback: %s", err.Error())
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	resp, err := oauth.Client(r.Context(), token).Get(provider.UserInfoEndpoint())
	if err != nil {
		h.logger.Printf("callback: %s", err.Error())
		w.WriteHeader(http.StatusBadRequest)

		return
	}
	defer func() { _ = resp.Body.Close() }()

	var userInfo auth.UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		h.logger.Printf("callback: %s", err.Error())
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	idTokenRaw, ok := token.Extra("id_token").(string)
	if ok {
		verifier := provider.Verifier(oidc.GetVerifierConfig(h.oauthConfig))
		idToken, err := verifier.Verify(r.Context(), idTokenRaw)
		if err != nil {
			h.logger.Printf("callback: %s", err.Error())
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		if err := idToken.Claims(&userInfo); err != nil {
			h.logger.Printf("callback: %s", err.Error())
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		if userInfo.Email == "" && strings.Contains(userInfo.Login, "@") {
			userInfo.Email = userInfo.Login
		}
	}

	jwt := auth.NewJWT(h.oauthConfig.JWTKey)
	session, err := jwt.Issue(&userInfo)
	if err != nil {
		h.logger.Printf("callback: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "state",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "return",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    session,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600,
	})

	http.Redirect(w, r, safeReturn(returnCookie.Value, r.Host), http.StatusFound)
}

func (h *Handler) info(w http.ResponseWriter, r *http.Request) {
	sessionCookie, err := r.Cookie("session")
	if err != nil {
		h.logger.Printf("info: %s", err.Error())
		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	jwt := auth.NewJWT(h.oauthConfig.JWTKey)
	userInfo, err := jwt.Parse(sessionCookie.Value)
	if err != nil {
		h.logger.Printf("info: %s", err.Error())
		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(&ModelSessionInfoGETResponseBody{
		Status:   true,
		UserInfo: userInfo,
	})
}
