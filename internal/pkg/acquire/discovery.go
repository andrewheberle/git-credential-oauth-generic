package acquire

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// protectedResourceMetadata is the RFC 9728 response from
// /.well-known/oauth-protected-resource.
type protectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
}

// authServerMetadata is the RFC 8414 response from
// /.well-known/oauth-authorization-server.
type authServerMetadata struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	RegistrationEndpoint          string   `json:"registration_endpoint"`
	ScopesSupported               []string `json:"scopes_supported"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`

	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

// dynamicClientResponse is the RFC 7591 registration response.
type dynamicClientResponse struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// discover performs RFC 9728 discovery against the protected resource host,
// then fetches RFC 8414 metadata from the first authorization server it names.
//
// Whether the host is an OAuth host at all is decided by the first step
// only: a 4xx, a response that isn't JSON, or metadata naming no
// authorization server mean it isn't (ErrNotOAuthHost), since this helper is
// usually configured for every host. Network errors, timeouts and 5xx there,
// and any failure once the host has said it is OAuth-protected, are
// ErrDiscovery.
func (a *Acquirer) discover(ctx context.Context, resourceURL, metadataHint string) (*authServerMetadata, error) {
	u, err := url.Parse(resourceURL)
	if err != nil {
		return nil, fmt.Errorf("%w: parsing resource URL: %w", ErrDiscovery, err)
	}

	prMeta, err := a.protectedResource(ctx, u, metadataHint)
	if err != nil {
		return nil, err
	}

	// Use the first authorization server.
	issuer := prMeta.AuthorizationServers[0]
	a.logger.Debug("authorization server", "url", issuer)

	asMeta, err := a.authServerMetadata(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: authorization server metadata: %w", ErrDiscovery, err)
	}

	// RFC 8414 §3.3: the metadata must be for the issuer it was fetched for.
	if !sameURL(asMeta.Issuer, issuer) {
		return nil, fmt.Errorf("%w: authorization server metadata is for issuer %q, not %q", ErrDiscovery, asMeta.Issuer, issuer)
	}

	return asMeta, nil
}

// protectedResource returns the protected resource metadata for resource.
//
// If Git passed a resource_metadata hint from the host's WWW-Authenticate
// challenge (RFC 9728 §5) and it is https on the same host and port, that
// document is tried first; its resource may be the Resource URL or any path
// under it, since the hint is issued for the URL Git requested. If the hint
// shows no OAuth metadata, or there is no usable hint, the well-known
// document at the root of the host is used, and its resource must be the
// Resource URL itself.
func (a *Acquirer) protectedResource(ctx context.Context, resource *url.URL, hint string) (*protectedResourceMetadata, error) {
	resourceURL := resource.String()

	if hint != "" {
		if !sameOrigin(resource, hint) {
			a.logger.Debug("ignoring resource_metadata hint: not https on the resource host", "hint", hint)
		} else {
			meta, err := a.fetchProtectedResource(ctx, hint)
			switch {
			case err == nil:
				if meta.Resource != "" && !sameURL(meta.Resource, resourceURL) && !underURL(meta.Resource, resourceURL) {
					return nil, fmt.Errorf("%w: hinted protected resource metadata is for %q, not under %q", ErrDiscovery, meta.Resource, resourceURL)
				}
				return meta, nil
			case errors.Is(err, ErrNotOAuthHost):
				a.logger.Debug("resource_metadata hint has no usable metadata; trying the well-known document", "hint", hint, "error", err)
			default:
				return nil, err
			}
		}
	}

	// RFC 9728: /.well-known/oauth-protected-resource at the resource host.
	meta, err := a.fetchProtectedResource(ctx, fmt.Sprintf("%s://%s/.well-known/oauth-protected-resource", resource.Scheme, resource.Host))
	if err != nil {
		return nil, err
	}
	// RFC 9728 §3.3: the metadata must be for this resource. A missing
	// resource is tolerated; a trailing slash is not a difference.
	if meta.Resource != "" && !sameURL(meta.Resource, resourceURL) {
		return nil, fmt.Errorf("%w: protected resource metadata is for %q, not %q", ErrDiscovery, meta.Resource, resourceURL)
	}
	return meta, nil
}

// fetchProtectedResource fetches protected resource metadata from metaURL.
// A 4xx, a response that isn't JSON, or metadata naming no authorization
// server is ErrNotOAuthHost; any other failure is ErrDiscovery.
func (a *Acquirer) fetchProtectedResource(ctx context.Context, metaURL string) (*protectedResourceMetadata, error) {
	a.logger.Debug("fetching protected resource metadata", "url", metaURL)
	var meta protectedResourceMetadata
	if err := a.fetchJSON(ctx, metaURL, &meta); err != nil {
		if hostIsNotOAuth(err) {
			return nil, fmt.Errorf("%w: %w", ErrNotOAuthHost, err)
		}
		return nil, fmt.Errorf("%w: protected resource metadata: %w", ErrDiscovery, err)
	}
	if len(meta.AuthorizationServers) == 0 {
		return nil, fmt.Errorf("%w: no authorization_servers in protected resource metadata", ErrNotOAuthHost)
	}
	return &meta, nil
}

// sameOrigin reports whether rawURL is https on the same host and port as
// resource (RFC 9728 §7: a hint must not steer discovery elsewhere).
func sameOrigin(resource *url.URL, rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || resource.Scheme != "https" {
		return false
	}
	return strings.EqualFold(u.Hostname(), resource.Hostname()) && portOrDefault(u) == portOrDefault(resource)
}

func portOrDefault(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	return "443"
}

// underURL reports whether candidate is a path under base.
func underURL(candidate, base string) bool {
	return strings.HasPrefix(candidate, strings.TrimSuffix(base, "/")+"/")
}

// authServerMetadata fetches the RFC 8414 metadata for issuer. The well-known
// path goes between the host and any path of the issuer (RFC 8414 §3.1). For
// an issuer with a path that has no such document, OpenID Connect discovery
// (path appended) is tried, which is where several identity providers
// publish the same metadata.
func (a *Acquirer) authServerMetadata(ctx context.Context, issuer string) (*authServerMetadata, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid authorization server URL %q", issuer)
	}
	path := strings.TrimSuffix(u.Path, "/")
	origin := u.Scheme + "://" + u.Host

	var meta authServerMetadata
	metaURL := origin + "/.well-known/oauth-authorization-server" + path
	a.logger.Debug("fetching authorization server metadata", "url", metaURL)
	err = a.fetchJSON(ctx, metaURL, &meta)
	if err == nil {
		return &meta, nil
	}

	var se *statusError
	if path == "" || !errors.As(err, &se) || se.code != http.StatusNotFound {
		return nil, err
	}

	oidcURL := origin + path + "/.well-known/openid-configuration"
	a.logger.Debug("no RFC 8414 metadata; trying OpenID Connect discovery", "url", oidcURL)
	if err := a.fetchJSON(ctx, oidcURL, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

// hostIsNotOAuth reports whether a failure fetching protected resource
// metadata means the host simply doesn't offer it: a client error status, or
// a response that isn't the expected JSON.
func hostIsNotOAuth(err error) bool {
	var se *statusError
	if errors.As(err, &se) {
		return se.code < http.StatusInternalServerError
	}
	var de *decodeError
	return errors.As(err, &de)
}

// sameURL compares two URLs as written, ignoring a trailing slash.
func sameURL(a, b string) bool {
	return strings.TrimSuffix(a, "/") == strings.TrimSuffix(b, "/")
}

// register performs RFC 7591 dynamic client registration, requesting the
// localhost redirect URI on the callback port. When the server supports
// public clients, it asks to be one: a command-line helper is a native app
// (RFC 8252), whose secret couldn't be kept confidential anyway, and a public
// client needs nothing in the OS keyring.
func (a *Acquirer) register(ctx context.Context, meta *authServerMetadata) (Client, error) {
	registrationEndpoint := meta.RegistrationEndpoint
	request := map[string]any{
		"redirect_uris": []string{a.redirectURL()},
		"client_name":   "git-credential-oauth-generic",
		"grant_types":   []string{"authorization_code", "refresh_token"},
	}
	if slices.Contains(meta.TokenEndpointAuthMethodsSupported, authNone) {
		request["token_endpoint_auth_method"] = authNone
	}
	body, err := json.Marshal(request)
	if err != nil {
		return Client{}, fmt.Errorf("encoding registration request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, registrationEndpoint, bytes.NewReader(body))
	if err != nil {
		return Client{}, fmt.Errorf("building registration request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return Client{}, fmt.Errorf("registration request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return Client{}, fmt.Errorf("registration failed (status %d): %s", resp.StatusCode, string(b))
	}
	var result dynamicClientResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return Client{}, fmt.Errorf("decoding registration response: %w", err)
	}
	if result.ClientID == "" {
		return Client{}, fmt.Errorf("registration response missing client_id")
	}
	return Client{ID: result.ClientID, Secret: result.ClientSecret, RedirectURI: a.redirectURL()}, nil
}

// fetchJSON fetches a URL and decodes the JSON response into dst.
func (a *Acquirer) fetchJSON(ctx context.Context, rawURL string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("building request for %s: %w", rawURL, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetching %s: %w", rawURL, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return &statusError{url: rawURL, code: resp.StatusCode}
	}
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		return &decodeError{url: rawURL, err: err}
	}
	return nil
}

// statusError is a metadata response with a status other than 200.
type statusError struct {
	url  string
	code int
}

func (e *statusError) Error() string {
	return fmt.Sprintf("unexpected status %d from %s", e.code, e.url)
}

// decodeError is a metadata response that isn't the expected JSON.
type decodeError struct {
	url string
	err error
}

func (e *decodeError) Error() string {
	return fmt.Sprintf("decoding response from %s: %v", e.url, e.err)
}

func (e *decodeError) Unwrap() error { return e.err }
