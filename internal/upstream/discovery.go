package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// Meta holds the OAuth endpoints discovered for an upstream.
type Meta struct {
	AuthorizationEndpoint             string
	TokenEndpoint                     string
	DCREndpoint                       string
	ClientIDMetadataDocumentSupported bool
}

type protectedResourceDoc struct {
	AuthorizationServers []string `json:"authorization_servers"`
}

type authServerDoc struct {
	AuthorizationEndpoint             string `json:"authorization_endpoint"`
	TokenEndpoint                     string `json:"token_endpoint"`
	RegistrationEndpoint              string `json:"registration_endpoint"`
	ClientIDMetadataDocumentSupported bool   `json:"client_id_metadata_document_supported"`
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
		// Discovery failed (e.g. well-known endpoint behind an auth proxy).
		// Create the upstream with the correct auth type but no endpoints; the
		// reconcile loop will retry discovery and populate them when it succeeds.
		slog.Warn("upstream: oauth2 discovery failed during probe; will retry via reconcile loop",
			"upstream", upstreamURL, "err", err)
		return &ProbeResult{AuthType: "oauth2_authorization_code"}, nil
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

// discoverFromWWWAuthenticate runs the full OAuth discovery chain.
//
// Step 1 — Protected Resource doc:
//   - If resource_metadata was provided in WWW-Authenticate, use that URL.
//   - Otherwise, try all RFC 9728 §5 well-known URL variants for the upstream.
//
// Step 2 — Authorization Server metadata:
//   - If we got an issuer from the PR doc, generate candidates from it.
//   - Otherwise fall back to generating candidates from the upstream URL itself.
//   - Tries RFC 8414 (with and without path) and OpenID Connect variants.
func discoverFromWWWAuthenticate(ctx context.Context, client *http.Client, upstreamURL, wwwAuth string) (*Meta, error) {
	// Use a redirect-limited client so a looping endpoint fails fast.
	dc := discoveryClient(client)

	// --- Step 1: protected resource doc ---
	var issuer string
	if prURL, err := extractResourceMetadata(wwwAuth); err == nil {
		// resource_metadata was provided — trust it, don't fall back.
		var pr protectedResourceDoc
		if err := getJSON(ctx, dc, prURL, &pr); err == nil && len(pr.AuthorizationServers) > 0 {
			issuer = pr.AuthorizationServers[0]
		}
	} else {
		// No resource_metadata: try all RFC 9728 §5 well-known variants.
		for _, prURL := range protectedResourceCandidates(upstreamURL) {
			var pr protectedResourceDoc
			if err := getJSON(ctx, dc, prURL, &pr); err == nil && len(pr.AuthorizationServers) > 0 {
				issuer = pr.AuthorizationServers[0]
				break
			}
		}
	}

	// --- Step 2: authorization server metadata ---
	// If we didn't find an issuer from the PR doc, derive candidates from the
	// upstream URL itself (some servers skip the PR doc layer entirely).
	source := issuer
	if source == "" {
		source = upstreamURL
	}
	candidates, err := authServerMetadataCandidates(source)
	if err != nil {
		return nil, fmt.Errorf("upstream: discover %s: build AS metadata URLs: %w", upstreamURL, err)
	}

	var lastErr error
	for _, asURL := range candidates {
		var as authServerDoc
		if err := getJSON(ctx, dc, asURL, &as); err != nil {
			lastErr = err
			continue
		}
		if as.AuthorizationEndpoint == "" && as.TokenEndpoint == "" {
			lastErr = fmt.Errorf("HTTP 200 but no endpoints at %s", asURL)
			continue
		}
		return &Meta{
			AuthorizationEndpoint:             as.AuthorizationEndpoint,
			TokenEndpoint:                     as.TokenEndpoint,
			DCREndpoint:                       as.RegistrationEndpoint,
			ClientIDMetadataDocumentSupported: as.ClientIDMetadataDocumentSupported,
		}, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no candidates found")
	}
	return nil, fmt.Errorf("upstream: discover %s: all AS metadata candidates failed: %w", upstreamURL, lastErr)
}

// discoveryClient wraps base with a redirect limiter (3 hops max) so looping
// well-known endpoints fail fast instead of spinning for 10 redirects.
func discoveryClient(base *http.Client) *http.Client {
	dc := *base
	dc.CheckRedirect = func(_ *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return fmt.Errorf("stopped after %d redirects", len(via))
		}
		return nil
	}
	return &dc
}

// protectedResourceCandidates returns the RFC 9728 §5 well-known URL variants
// for a protected resource URL, tried in order when no resource_metadata hint
// is present in the WWW-Authenticate header.
func protectedResourceCandidates(rawURL string) []string {
	u, err := url.Parse(strings.TrimRight(rawURL, "/"))
	if err != nil {
		return nil
	}
	base := u.Scheme + "://" + u.Host
	var out []string
	if u.Path != "" && u.Path != "/" {
		// RFC 9728 §5: insert .well-known before the path.
		out = append(out, base+"/.well-known/oauth-protected-resource"+u.Path)
	}
	out = append(out, base+"/.well-known/oauth-protected-resource")
	return out
}

// authServerMetadataCandidates returns OAuth AS metadata URLs to try for a
// given issuer, covering RFC 8414 and OpenID Connect variants.
//
// For issuer https://host/path the candidates are:
//  1. https://host/.well-known/oauth-authorization-server         (RFC 8414, no path)
//  2. https://host/.well-known/oauth-authorization-server/path    (RFC 8414, path appended)
//  3. https://host/path/.well-known/oauth-authorization-server    (RFC 8414, path before .well-known)
//  4. https://host/.well-known/openid-configuration               (OIDC, no path)
//  5. https://host/path/.well-known/openid-configuration          (OIDC, Keycloak-style)
func authServerMetadataCandidates(issuer string) ([]string, error) {
	u, err := url.Parse(strings.TrimRight(issuer, "/"))
	if err != nil {
		return nil, err
	}
	base := u.Scheme + "://" + u.Host
	path := u.Path

	out := []string{
		base + "/.well-known/oauth-authorization-server",
	}
	if path != "" && path != "/" {
		out = append(out, base+"/.well-known/oauth-authorization-server"+path)
		out = append(out, base+path+"/.well-known/oauth-authorization-server")
	}
	out = append(out, base+"/.well-known/openid-configuration")
	if path != "" && path != "/" {
		out = append(out, base+path+"/.well-known/openid-configuration")
	}
	return out, nil
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
