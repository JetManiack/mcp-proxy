package upstream_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JetManiack/mcp-proxy/internal/upstream"
)

func TestDiscover_HappyPath(t *testing.T) {
	authServerURL := ""

	// Auth server: serves /.well-known/oauth-authorization-server
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/oauth-authorization-server" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"authorization_endpoint": authServerURL + "/authorize",
			"token_endpoint":         authServerURL + "/token",
			"registration_endpoint":  authServerURL + "/register",
		})
	}))
	defer authSrv.Close()
	authServerURL = authSrv.URL

	// Resource server: serves /.well-known/oauth-protected-resource
	resourceSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/oauth-protected-resource" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"authorization_servers": []string{authSrv.URL},
		})
	}))
	defer resourceSrv.Close()

	meta, err := upstream.Discover(context.Background(), http.DefaultClient, resourceSrv.URL)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if meta.AuthorizationEndpoint != authServerURL+"/authorize" {
		t.Errorf("AuthorizationEndpoint: got %q", meta.AuthorizationEndpoint)
	}
	if meta.TokenEndpoint != authServerURL+"/token" {
		t.Errorf("TokenEndpoint: got %q", meta.TokenEndpoint)
	}
	if meta.DCREndpoint != authServerURL+"/register" {
		t.Errorf("DCREndpoint: got %q", meta.DCREndpoint)
	}
}

func TestDiscover_MissingAuthorizationServers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"authorization_servers": []string{},
		})
	}))
	defer srv.Close()

	_, err := upstream.Discover(context.Background(), http.DefaultClient, srv.URL)
	if err == nil {
		t.Fatal("expected error for empty authorization_servers, got nil")
	}
}

func TestDiscover_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := upstream.Discover(context.Background(), http.DefaultClient, srv.URL)
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}
