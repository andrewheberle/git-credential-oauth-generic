package acquire

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// protectedResourceMetadata is the RFC 9728 response from
// /.well-known/oauth-protected-resource.
type protectedResourceMetadata struct {
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
}

// dynamicClientResponse is the RFC 7591 registration response.
type dynamicClientResponse struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// discover performs RFC 9728 discovery against the protected resource host,
// then fetches RFC 8414 metadata from the first authorization server it names.
func (a *Acquirer) discover(ctx context.Context, resourceURL string) (*authServerMetadata, error) {
	u, err := url.Parse(resourceURL)
	if err != nil {
		return nil, fmt.Errorf("parsing resource URL: %w", err)
	}

	// RFC 9728: fetch /.well-known/oauth-protected-resource from the resource host.
	prMetaURL := fmt.Sprintf("%s://%s/.well-known/oauth-protected-resource", u.Scheme, u.Host)
	a.logger.Debug("fetching protected resource metadata", "url", prMetaURL)
	var prMeta protectedResourceMetadata
	if err := a.fetchJSON(ctx, prMetaURL, &prMeta); err != nil {
		return nil, fmt.Errorf("RFC 9728 discovery: %w", err)
	}
	if len(prMeta.AuthorizationServers) == 0 {
		return nil, fmt.Errorf("no authorization_servers in protected resource metadata")
	}

	// Use the first authorization server.
	asBase := prMeta.AuthorizationServers[0]
	a.logger.Debug("authorization server", "url", asBase)

	// RFC 8414: fetch /.well-known/oauth-authorization-server from the AS.
	asParsed, err := url.Parse(asBase)
	if err != nil {
		return nil, fmt.Errorf("parsing authorization server URL: %w", err)
	}
	asMetaURL := fmt.Sprintf("%s://%s/.well-known/oauth-authorization-server", asParsed.Scheme, asParsed.Host)
	a.logger.Debug("fetching authorization server metadata", "url", asMetaURL)
	var asMeta authServerMetadata
	if err := a.fetchJSON(ctx, asMetaURL, &asMeta); err != nil {
		return nil, fmt.Errorf("RFC 8414 metadata: %w", err)
	}
	return &asMeta, nil
}

// register performs RFC 7591 dynamic client registration, requesting the
// localhost redirect URI on the callback port.
func (a *Acquirer) register(ctx context.Context, registrationEndpoint string) (Client, error) {
	body, err := json.Marshal(map[string]any{
		"redirect_uris": []string{a.redirectURL()},
		"client_name":   "git-credential-oauth-generic",
		"grant_types":   []string{"authorization_code", "refresh_token"},
	})
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
		return fmt.Errorf("unexpected status %d from %s", resp.StatusCode, rawURL)
	}
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		return fmt.Errorf("decoding response from %s: %w", rawURL, err)
	}
	return nil
}
