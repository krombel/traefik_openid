package traefik_openid

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServeHTTP(t *testing.T) {
	// Setup
	config := CreateConfig()
	config.ProviderURL = "https://keycloak.vistameet.eu/realms/vm-dev01"
	config.ClientID = "traefikMiddleware"
	config.ClientSecret = "v3gztdimWH8yD2sn3b8ZUisbhvdQHsg7"

	// Create a new instance of our middleware
	openIDMiddleware, err := New(context.TODO(), http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}), config, "openid")
	if err != nil {
		t.Fatal("Expected no error while creating openid middleware, got:", err)
	}

	fmt.Printf("%+v\n", openIDMiddleware)
	req, err := http.NewRequest("GET", "https://vistameet.eu/", nil)
	if err != nil {
		t.Fatal("Expected no error while creating http request, got:", err)
	}

	rw := httptest.NewRecorder()

	// Test
	openIDMiddleware.ServeHTTP(rw, req)

	fmt.Printf("%+v\n", rw)
	fmt.Printf("==>>>%+v\n", req)
}
