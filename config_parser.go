package traefik_openid

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

type Config struct {
	ProviderURL    string `json:"url"`
	ClientID       string `json:"client_id"`
	ClientSecret   string `json:"client_secret"`
	UserClaimName  string `json:"user_claim_name"`
	UserHeaderName string `json:"user_header_name"`
	Scopes         string `json:"scopes"`

	ClientIDFile     string `json:"client_id_file"`
	ClientSecretFile string `json:"client_secret_file"`
	ProviderURLEnv   string `json:"url_env"`
	ClientIDEnv      string `json:"client_id_env"`
	ClientSecretEnv  string `json:"client_secret_env"`
}

type oidcAuth struct {
	next           http.Handler
	ProviderURL    *url.URL
	ClientID       string
	ClientSecret   string
	Scopes         []string
	UserClaimName  string
	UserHeaderName string
	OidcProvider   *oidc.Provider
}

type state struct {
	RedirectURL string `json:"redirect_url"`
}

func CreateConfig() *Config {
	return &Config{}
}

func parseUrl(rawUrl string) (*url.URL, error) {
	if rawUrl == "" {
		return nil, errors.New("invalid empty url")
	}
	if !strings.Contains(rawUrl, "://") {
		rawUrl = "https://" + rawUrl
	}
	u, err := url.Parse(rawUrl)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(u.Scheme, "http") {
		return nil, fmt.Errorf("%v is not a valid scheme", u.Scheme)
	}
	return u, nil
}

func readSecretFiles(config *Config) error {
	if config.ClientIDFile != "" {
		id, err := os.ReadFile(config.ClientIDFile)
		if err != nil {
			return err
		}
		clientId := string(id)
		clientId = strings.TrimSpace(clientId)
		clientId = strings.TrimSuffix(clientId, "\n")
		config.ClientID = clientId
	}
	if config.ClientSecretFile != "" {
		secret, err := os.ReadFile(config.ClientSecretFile)
		if err != nil {
			return err
		}
		clientSecret := string(secret)
		clientSecret = strings.TrimSpace(clientSecret)
		clientSecret = strings.TrimSuffix(clientSecret, "\n")
		config.ClientSecret = clientSecret
	}
	return nil
}

func readConfigEnv(config *Config) error {
	if config.ProviderURLEnv != "" {
		providerURL := os.Getenv(config.ProviderURLEnv)
		if providerURL == "" {
			return errors.New("ProviderURLEnv referenced but NOT set")
		}
		config.ProviderURL = strings.TrimSpace(providerURL)
	}
	if config.ClientIDEnv != "" {
		clientId := os.Getenv(config.ClientIDEnv)
		if clientId == "" {
			return errors.New("ClientIDEnv referenced but NOT set")
		}
		config.ClientID = strings.TrimSpace(clientId)
	}
	if config.ClientSecretEnv != "" {
		clientSecret := os.Getenv(config.ClientSecretEnv)
		if clientSecret == "" {
			return errors.New("ClientSecretEnv referenced but NOT set")
		}
		config.ClientSecret = strings.TrimSpace(clientSecret)
	}
	return nil
}

func New(uctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	err := readSecretFiles(config)
	if err != nil {
		return nil, err
	}
	err = readConfigEnv(config)
	if err != nil {
		return nil, err
	}

	if config.ClientID == "" {
		return nil, errors.New("invalid configuration")
	}

	parsedURL, err := parseUrl(config.ProviderURL)
	if err != nil {
		return nil, err
	}

	oidcProvider, err := oidc.NewProvider(uctx, parsedURL.String())
	if err != nil {
		return nil, err
	}

	var scopes []string
	if len(config.Scopes) > 0 {
		scopes = strings.Split(config.Scopes, " ")
	} else {
		scopes = []string{oidc.ScopeOpenID}
	}
	if scopes[0] != oidc.ScopeOpenID {
		return nil, errors.New("scope need to start with " + oidc.ScopeOpenID)
	}

	userClaimName := "preferred_username"
	if config.UserClaimName != "" {
		userClaimName = config.UserClaimName
	}

	userHeaderName := "X-Forwarded-User"
	if config.UserHeaderName != "" {
		userHeaderName = config.UserHeaderName
	}

	return &oidcAuth{
		next:           next,
		ProviderURL:    parsedURL,
		ClientID:       config.ClientID,
		ClientSecret:   config.ClientSecret,
		UserClaimName:  userClaimName,
		UserHeaderName: userHeaderName,
		OidcProvider:   oidcProvider,
	}, nil
}
