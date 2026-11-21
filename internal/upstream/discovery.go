package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// Meta holds the OAuth endpoints discovered for an upstream.
type Meta struct {
	AuthorizationEndpoint string
	TokenEndpoint         string
	DCREndpoint           string
}

type protectedResourceDoc struct {
	AuthorizationServers []string `json:"authorization_servers"`
}

type authServerDoc struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	RegistrationEndpoint  string `json:"registration_endpoint"`
}

// Discover fetches OAuth endpoint metadata for an upstream by probing it for a
// 401 WWW-Authenticate challenge and following the RFC 9728 discovery chain.
func Discover(ctx context.Context, client *http.Client, upstreamURL string) (*Meta, error) {
	// Probe to get the WWW-Authenticate header with resource_metadata.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstreamURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("upstream: discover %s: %w", upstreamURL, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	return discoverFromWWWAuthenticate(ctx, client, upstreamURL, wwwAuth)
}

// ProbeResult holds the auto-detected auth type and, for oauth2, the full
// OAuth endpoint metadata.
type ProbeResult struct {
	AuthType string // "none" | "bearer_static" | "oauth2_authorization_code" | "basic_auth" | "api_key"
	Meta     *Meta  // non-nil when AuthType == "oauth2_authorization_code"
}

// ProbeAuthType probes upstreamURL to detect which auth type the server
// requires, then (for oauth2) follows the full discovery chain.
//
// Detection rules (applied to the 401 WWW-Authenticate header):
//   - Bearer + resource_metadata → oauth2_authorization_code  (RFC 9728)
//   - Bearer (no resource_metadata) → bearer_static
//   - Basic → basic_auth
//   - ApiKey / Api-Key → api_key
//   - 200 / no WWW-Authenticate → none
func ProbeAuthType(ctx context.Context, client *http.Client, upstreamURL string) (*ProbeResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstreamURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("probe %s: %w", upstreamURL, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return &ProbeResult{AuthType: "none"}, nil
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return nil, fmt.Errorf("probe %s: unexpected status %d", upstreamURL, resp.StatusCode)
	}

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	authType := parseWWWAuthenticate(wwwAuth)

	if authType != "oauth2_authorization_code" {
		return &ProbeResult{AuthType: authType}, nil
	}

	// oauth2: run full discovery chain.
	meta, err := discoverFromWWWAuthenticate(ctx, client, upstreamURL, wwwAuth)
	if err != nil {
		return nil, err
	}
	return &ProbeResult{AuthType: "oauth2_authorization_code", Meta: meta}, nil
}

// parseWWWAuthenticate classifies a WWW-Authenticate header value into one of
// the supported auth type strings.
func parseWWWAuthenticate(header string) string {
	lower := strings.ToLower(header)
	switch {
	case strings.Contains(lower, "resource_metadata="):
		return "oauth2_authorization_code"
	case strings.HasPrefix(lower, "bearer"):
		return "bearer_static"
	case strings.HasPrefix(lower, "basic"):
		return "basic_auth"
	case strings.Contains(lower, "apikey"), strings.Contains(lower, "api-key"), strings.Contains(lower, "api_key"):
		return "api_key"
	default:
		return "none"
	}
}

// discoverFromWWWAuthenticate runs the full OAuth discovery chain starting from
// the resource_metadata URL found in the WWW-Authenticate header.
func discoverFromWWWAuthenticate(ctx context.Context, client *http.Client, upstreamURL, wwwAuth string) (*Meta, error) {
	prURL, err := extractResourceMetadata(wwwAuth)
	if err != nil {
		// Fall back to RFC 9728 §5 path construction.
		prURL, err = protectedResourceWellKnown(upstreamURL)
		if err != nil {
			return nil, fmt.Errorf("upstream: discover %s: build well-known URL: %w", upstreamURL, err)
		}
	}

	var pr protectedResourceDoc
	if err := getJSON(ctx, client, prURL, &pr); err != nil {
		return nil, fmt.Errorf("upstream: discover %s: %w", upstreamURL, err)
	}
	if len(pr.AuthorizationServers) == 0 {
		return nil, fmt.Errorf("upstream: discover %s: no authorization_servers in protected resource doc", upstreamURL)
	}

	asURL := strings.TrimRight(pr.AuthorizationServers[0], "/") + "/.well-known/oauth-authorization-server"
	var as authServerDoc
	if err := getJSON(ctx, client, asURL, &as); err != nil {
		return nil, fmt.Errorf("upstream: discover auth server %s: %w", pr.AuthorizationServers[0], err)
	}
	return &Meta{
		AuthorizationEndpoint: as.AuthorizationEndpoint,
		TokenEndpoint:         as.TokenEndpoint,
		DCREndpoint:           as.RegistrationEndpoint,
	}, nil
}

// extractResourceMetadata parses the resource_metadata="<url>" token from a
// WWW-Authenticate Bearer challenge (RFC 9728 §7).
func extractResourceMetadata(header string) (string, error) {
	const key = `resource_metadata="`
	idx := strings.Index(header, key)
	if idx < 0 {
		return "", fmt.Errorf("no resource_metadata in WWW-Authenticate header")
	}
	rest := header[idx+len(key):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return "", fmt.Errorf("unterminated resource_metadata value in WWW-Authenticate")
	}
	return rest[:end], nil
}

// protectedResourceWellKnown builds the RFC 9728 §5 well-known URL for a
// protected resource. The `.well-known/oauth-protected-resource` segment is
// inserted after the authority and before any existing path component, so
// https://host/svc → https://host/.well-known/oauth-protected-resource/svc.
func protectedResourceWellKnown(rawURL string) (string, error) {
	u, err := url.Parse(strings.TrimRight(rawURL, "/"))
	if err != nil {
		return "", err
	}
	u.Path = "/.well-known/oauth-protected-resource" + u.Path
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

func getJSON(ctx context.Context, client *http.Client, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

// ValidateUpstreamURL checks that raw is a valid http/https URL and that the
// host is not a loopback or link-local address. It is intentionally permissive
// about the scheme (http is allowed for local dev) but blocks SSRF targets.
func ValidateUpstreamURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("upstream URL is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("upstream URL: %w", err)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return fmt.Errorf("upstream URL: scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("upstream URL: missing host")
	}
	if u.User != nil {
		return fmt.Errorf("upstream URL: must not contain credentials")
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return fmt.Errorf("upstream URL: host %q is not allowed", host)
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("upstream URL: address %q is not allowed (loopback/link-local)", host)
		}
	}
	return nil
}

// requireHTTPS validates that raw is a well-formed https URL with a non-empty
// host and no embedded credentials.
func requireHTTPS(name, raw string) error {
	if raw == "" {
		return fmt.Errorf("%s is empty", name)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s: invalid URL: %w", name, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%s must use https, got %q", name, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("%s has no host", name)
	}
	if u.User != nil {
		return fmt.Errorf("%s must not contain credentials", name)
	}
	return nil
}
