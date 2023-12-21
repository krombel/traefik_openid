package traefik_openid

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func (k *oidcAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	cookie, err := req.Cookie("Authorization")
	if err == nil && strings.HasPrefix(cookie.Value, "Bearer ") {
		token := strings.TrimPrefix(cookie.Value, "Bearer ")
		fmt.Printf("token = %+v\n", token)

		idToken, err := k.verifyToken(req.Context(), token)
		fmt.Printf("ok = %+v\n", idToken != nil)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		if idToken == nil {
			qry := req.URL.Query()
			qry.Del("code")
			qry.Del("state")
			qry.Del("session_state")
			req.URL.RawQuery = qry.Encode()
			req.RequestURI = req.URL.RequestURI()

			expiration := time.Now().Add(-24 * time.Hour)
			newCookie := &http.Cookie{
				Name:    "Authorization",
				Value:   "",
				Path:    "/",
				Expires: expiration,
				MaxAge:  -1,
			}
			http.SetCookie(rw, newCookie)

			k.redirectToOpenIDProvider(rw, req)
			return
		}
		user, err := extractClaims(idToken, k.UserClaimName)
		if err == nil {
			req.Header.Set(k.UserHeaderName, user)
		}
		k.next.ServeHTTP(rw, req)
	} else {
		authCode := req.URL.Query().Get("code")
		if authCode == "" {
			fmt.Printf("code is missing, redirect to openid provider\n")
			k.redirectToOpenIDProvider(rw, req)
			return
		}

		stateBase64 := req.URL.Query().Get("state")
		if stateBase64 == "" {
			fmt.Printf("state is missing, redirect to openid provider\n")
			k.redirectToOpenIDProvider(rw, req)
			return
		}

		fmt.Printf("exchange auth code called\n")
		token, err := k.exchangeAuthCode(req, authCode, stateBase64)
		fmt.Printf("exchange auth code finished %+v\n", token)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		http.SetCookie(rw, &http.Cookie{
			Name:     "Authorization",
			Value:    "Bearer " + token,
			Secure:   true,
			HttpOnly: true,
			Path:     "/",
			SameSite: http.SameSiteStrictMode,
		})

		qry := req.URL.Query()
		qry.Del("code")
		qry.Del("state")
		qry.Del("session_state")
		req.URL.RawQuery = qry.Encode()
		req.RequestURI = req.URL.RequestURI()

		scheme := req.Header.Get("X-Forwarded-Proto")
		host := req.Header.Get("X-Forwarded-Host")
		originalURL := fmt.Sprintf("%s://%s%s", scheme, host, req.RequestURI)

		http.Redirect(rw, req, originalURL, http.StatusFound)
	}
}

func extractClaims(idToken *oidc.IDToken, claimName string) (string, error) {
	var claims map[string]interface{}
	idToken.Claims(&claims)

	if claimValue, ok := claims[claimName]; ok {
		return fmt.Sprintf("%v", claimValue), nil
	}
	return "", fmt.Errorf("missing claim %s", claimName)
}

func (k *oidcAuth) exchangeAuthCode(req *http.Request, authCode string, stateBase64 string) (string, error) {
	stateBytes, _ := base64.StdEncoding.DecodeString(stateBase64)
	var state state
	err := json.Unmarshal(stateBytes, &state)
	if err != nil {
		return "", err
	}

	cfg := oauth2.Config{
		ClientID:     k.ClientID,
		ClientSecret: k.ClientSecret,
		Endpoint:     k.OidcProvider.Endpoint(),
		RedirectURL:  state.RedirectURL,
		Scopes:       k.Scopes,
	}
	token, err := cfg.Exchange(req.Context(), authCode)

	idToken := token.Extra("id_token").(string)
	if len(idToken) > 0 {
		// return jwks token
		return idToken, err
	}
	// jwks not supported
	return "", errors.Join(errors.New("only jwks is supported"), err)
}

func (k *oidcAuth) redirectToOpenIDProvider(rw http.ResponseWriter, req *http.Request) {
	scheme := req.Header.Get("X-Forwarded-Proto")
	host := req.Header.Get("X-Forwarded-Host")
	originalURL := fmt.Sprintf("%s://%s%s", scheme, host, req.RequestURI)

	state := state{
		RedirectURL: originalURL,
	}

	stateBytes, _ := json.Marshal(state)
	stateBase64 := base64.StdEncoding.EncodeToString(stateBytes)

	cfg := oauth2.Config{
		ClientID:     k.ClientID,
		ClientSecret: k.ClientSecret,
		Endpoint:     k.OidcProvider.Endpoint(),
		RedirectURL:  state.RedirectURL,
		Scopes:       k.Scopes,
	}

	http.Redirect(rw, req, cfg.AuthCodeURL(stateBase64), http.StatusFound)
}

func (k *oidcAuth) verifyToken(ctx context.Context, token string) (*oidc.IDToken, error) {
	idToken, err := k.OidcProvider.Verifier(&oidc.Config{
		ClientID: k.ClientID,
	}).Verify(ctx, token)

	return idToken, err
}
