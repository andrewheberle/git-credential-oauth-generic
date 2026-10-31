package acquire

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// Client authentication methods at the token endpoint (RFC 7591 §2).
const (
	authNone              = "none"
	authClientSecretBasic = "client_secret_basic"
	authClientSecretPost  = "client_secret_post"
)

// maxTokenResponse bounds how much of a token endpoint response is read.
const maxTokenResponse = 1 << 20

// tokenEndpoint makes the token requests for one Registered client at one
// authorization server: the code exchange (RFC 6749 §4.1.3, with PKCE) and
// refresh (RFC 6749 §6). Both always carry the Resource URL (RFC 8707 §2.2)
// and authenticate the client the same way.
type tokenEndpoint struct {
	httpClient  *http.Client
	url         string
	client      Client
	authMethod  string
	resource    string
	redirectURI string
}

// tokenEndpoint returns the token endpoint for client. A public client (no
// secret) sends only its client_id. A confidential client uses HTTP Basic
// authentication, the RFC 8414 default, unless the server lists only
// client_secret_post.
func (a *Acquirer) tokenEndpoint(meta *authServerMetadata, client Client, resourceURL string) *tokenEndpoint {
	method := authNone
	if client.Secret != "" {
		method = authClientSecretBasic
		supported := meta.TokenEndpointAuthMethodsSupported
		if len(supported) > 0 && !slices.Contains(supported, authClientSecretBasic) && slices.Contains(supported, authClientSecretPost) {
			method = authClientSecretPost
		}
	}
	return &tokenEndpoint{
		httpClient:  a.httpClient,
		url:         meta.TokenEndpoint,
		client:      client,
		authMethod:  method,
		resource:    resourceURL,
		redirectURI: a.redirectURL(),
	}
}

// exchange trades an authorization code and its PKCE verifier for a token.
// It is the Exchange given to the Authorizer.
func (t *tokenEndpoint) exchange(ctx context.Context, code, verifier string) (*oauth2.Token, error) {
	return t.request(ctx, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {t.redirectURI},
	})
}

// refresh trades refreshToken for a new token. If the response carries no
// refresh token, refreshToken stays valid and is kept (RFC 6749 §6).
func (t *tokenEndpoint) refresh(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	token, err := t.request(ctx, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	})
	if err != nil {
		return nil, err
	}
	if token.RefreshToken == "" {
		token.RefreshToken = refreshToken
	}
	return token, nil
}

// tokenRejectedError is an OAuth error response from the token endpoint
// (RFC 6749 §5.2): the server understood the request and refused it, as
// when a refresh token has expired or been revoked (invalid_grant).
type tokenRejectedError struct {
	code        string
	description string
}

func (e *tokenRejectedError) Error() string {
	if e.description == "" {
		return "token request rejected: " + e.code
	}
	return fmt.Sprintf("token request rejected: %s: %s", e.code, e.description)
}

// tokenResponse is a successful token response (RFC 6749 §5.1).
type tokenResponse struct {
	AccessToken  string      `json:"access_token"`
	TokenType    string      `json:"token_type"`
	ExpiresIn    json.Number `json:"expires_in"`
	RefreshToken string      `json:"refresh_token"`
}

// errorResponse is an error token response (RFC 6749 §5.2).
type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// request POSTs form to the token endpoint with the resource and client
// authentication added. It returns a *tokenRejectedError for an OAuth error
// response; any other error (network, timeout, 5xx, a response that isn't
// OAuth) means the endpoint could not be used right now.
func (t *tokenEndpoint) request(ctx context.Context, form url.Values) (*oauth2.Token, error) {
	form.Set("resource", t.resource)
	switch t.authMethod {
	case authNone:
		form.Set("client_id", t.client.ID)
	case authClientSecretPost:
		form.Set("client_id", t.client.ID)
		form.Set("client_secret", t.client.Secret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("building token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if t.authMethod == authClientSecretBasic {
		// RFC 6749 §2.3.1: both parts are form-encoded before Basic encoding.
		req.SetBasicAuth(url.QueryEscape(t.client.ID), url.QueryEscape(t.client.Secret))
	}

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponse))
	if err != nil {
		return nil, fmt.Errorf("reading token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var e errorResponse
		if resp.StatusCode >= 400 && resp.StatusCode < 500 && json.Unmarshal(body, &e) == nil && e.Error != "" {
			return nil, &tokenRejectedError{code: e.Error, description: e.ErrorDescription}
		}
		return nil, fmt.Errorf("token endpoint returned status %d", resp.StatusCode)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("decoding token response: %w", err)
	}
	if tr.AccessToken == "" {
		return nil, errors.New("token response has no access_token")
	}
	if !strings.EqualFold(tr.TokenType, "bearer") {
		return nil, fmt.Errorf("unsupported token type %q (only Bearer tokens can be given to Git)", tr.TokenType)
	}

	token := &oauth2.Token{AccessToken: tr.AccessToken, TokenType: "Bearer", RefreshToken: tr.RefreshToken}
	if tr.ExpiresIn != "" {
		secs, err := tr.ExpiresIn.Int64()
		if err != nil {
			return nil, fmt.Errorf("invalid expires_in %q in token response", tr.ExpiresIn)
		}
		if secs > 0 {
			token.Expiry = time.Now().Add(time.Duration(secs) * time.Second)
		}
	}
	return token, nil
}
