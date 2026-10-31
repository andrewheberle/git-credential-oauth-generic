package acquire

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// route is one canned response of the discovery test server. "{{URL}}" in
// body is replaced with the server's URL.
type route struct {
	status int
	body   string
	delay  time.Duration
}

// Cloudflare Access managed OAuth metadata, as returned by a real deployment,
// with its hostnames pointed at the test server: the
// protected resource (a Workers app) and the Access team domain acting as
// authorization server are both {{URL}} here.
const (
	cloudflareResourceMeta = `{"resource":"{{URL}}","authorization_servers":["{{URL}}"]}`
	cloudflareASMeta       = `{"issuer":"{{URL}}","authorization_endpoint":"{{URL}}/cdn-cgi/access/oauth/authorization","token_endpoint":"{{URL}}/cdn-cgi/access/oauth/token","response_types_supported":["code"],"response_modes_supported":["query"],"grant_types_supported":["authorization_code","refresh_token"],"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","none"],"revocation_endpoint":"{{URL}}/cdn-cgi/access/oauth/revoke","registration_endpoint":"{{URL}}/cdn-cgi/access/oauth/registration","code_challenge_methods_supported":["S256"]}`
)

const (
	prPath   = "/.well-known/oauth-protected-resource"
	asPath   = "/.well-known/oauth-authorization-server"
	slowStep = time.Second
)

func ok(body string) route { return route{status: http.StatusOK, body: body} }

func TestDiscovery(t *testing.T) {
	asMeta := func(issuer string) string {
		return `{"issuer":"` + issuer + `","authorization_endpoint":"{{URL}}/authorize","token_endpoint":"{{URL}}/token"}`
	}

	tests := []struct {
		name    string
		routes  map[string]route
		wantErr error // nil means the sign-in completes
	}{
		{
			name:   "Cloudflare Access managed OAuth",
			routes: map[string]route{prPath: ok(cloudflareResourceMeta), asPath: ok(cloudflareASMeta)},
		},

		// Step 1: is this an OAuth host at all?
		{name: "no protected resource metadata (404)", routes: map[string]route{}, wantErr: ErrNotOAuthHost},
		{name: "protected resource metadata forbidden (403)", routes: map[string]route{prPath: {status: http.StatusForbidden}}, wantErr: ErrNotOAuthHost},
		{name: "HTML page instead of metadata", routes: map[string]route{prPath: ok("<!doctype html><title>Sign in</title>")}, wantErr: ErrNotOAuthHost},
		{name: "metadata naming no authorization server", routes: map[string]route{prPath: ok(`{"resource":"{{URL}}"}`)}, wantErr: ErrNotOAuthHost},
		{name: "protected resource metadata server error", routes: map[string]route{prPath: {status: http.StatusBadGateway}}, wantErr: ErrDiscovery},
		{name: "protected resource metadata times out", routes: map[string]route{prPath: {status: http.StatusOK, body: cloudflareResourceMeta, delay: slowStep}}, wantErr: ErrDiscovery},

		// RFC 9728 §3.3: the metadata must be for this resource.
		{
			name:    "metadata for a different resource",
			routes:  map[string]route{prPath: ok(`{"resource":"https://elsewhere.example.com","authorization_servers":["{{URL}}"]}`), asPath: ok(asMeta("{{URL}}"))},
			wantErr: ErrDiscovery,
		},
		{
			name:   "resource with a trailing slash",
			routes: map[string]route{prPath: ok(`{"resource":"{{URL}}/","authorization_servers":["{{URL}}"]}`), asPath: ok(asMeta("{{URL}}"))},
		},
		{
			name:   "resource missing",
			routes: map[string]route{prPath: ok(`{"authorization_servers":["{{URL}}"]}`), asPath: ok(asMeta("{{URL}}"))},
		},

		// Step 2: once the host is OAuth-protected, failures are reported.
		{name: "authorization server metadata missing", routes: map[string]route{prPath: ok(cloudflareResourceMeta)}, wantErr: ErrDiscovery},
		{name: "authorization server metadata server error", routes: map[string]route{prPath: ok(cloudflareResourceMeta), asPath: {status: http.StatusServiceUnavailable}}, wantErr: ErrDiscovery},
		{name: "authorization server metadata not JSON", routes: map[string]route{prPath: ok(cloudflareResourceMeta), asPath: ok("<html>")}, wantErr: ErrDiscovery},
		{name: "authorization server metadata times out", routes: map[string]route{prPath: ok(cloudflareResourceMeta), asPath: {status: http.StatusOK, body: cloudflareASMeta, delay: slowStep}}, wantErr: ErrDiscovery},

		// RFC 8414 §3.3: the metadata must be for the issuer it was fetched for.
		{name: "metadata for a different issuer", routes: map[string]route{prPath: ok(cloudflareResourceMeta), asPath: ok(asMeta("https://attacker.example.com"))}, wantErr: ErrDiscovery},
		{name: "metadata without an issuer", routes: map[string]route{prPath: ok(cloudflareResourceMeta), asPath: ok(`{"authorization_endpoint":"{{URL}}/authorize","token_endpoint":"{{URL}}/token"}`)}, wantErr: ErrDiscovery},
		{name: "issuer with a trailing slash", routes: map[string]route{prPath: ok(cloudflareResourceMeta), asPath: ok(asMeta("{{URL}}/"))}},

		// RFC 8414 §3.1: issuers with a path.
		{
			name: "issuer with a path uses the path-inserted well-known URL",
			routes: map[string]route{
				prPath:               ok(`{"resource":"{{URL}}","authorization_servers":["{{URL}}/realms/x"]}`),
				asPath + "/realms/x": ok(asMeta("{{URL}}/realms/x")),
			},
		},
		{
			name: "issuer with a path falls back to OpenID Connect discovery",
			routes: map[string]route{
				prPath: ok(`{"resource":"{{URL}}","authorization_servers":["{{URL}}/realms/x"]}`),
				"/realms/x/.well-known/openid-configuration": ok(asMeta("{{URL}}/realms/x")),
			},
		},
		{
			name: "issuer with a path ignores metadata at the host root",
			routes: map[string]route{
				prPath: ok(`{"resource":"{{URL}}","authorization_servers":["{{URL}}/realms/x"]}`),
				asPath: ok(asMeta("{{URL}}")),
			},
			wantErr: ErrDiscovery,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var srv *httptest.Server
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				rt, found := tt.routes[r.URL.Path]
				if !found {
					http.NotFound(w, r)
					return
				}
				if rt.delay > 0 {
					select {
					case <-time.After(rt.delay):
					case <-r.Context().Done():
						return
					}
				}
				w.WriteHeader(rt.status)
				_, _ = w.Write([]byte(strings.ReplaceAll(rt.body, "{{URL}}", srv.URL)))
			}))
			t.Cleanup(srv.Close)

			client := srv.Client()
			client.Timeout = slowStep / 4

			reg := newFakeRegistry()
			reg.clients[srv.URL] = Client{ID: "known-id"}
			auth := &fakeAuthorizer{token: validToken("login-at")}

			a := New(Config{
				Cache:        newFakeCache(),
				Clients:      reg,
				Authorize:    auth.authorize,
				HTTPClient:   client,
				CallbackPort: callbackPort,
			})
			token, err := a.Acquire(context.Background(), srv.URL)

			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("Acquire: unexpected error: %v", err)
				}
				if token == nil || token.AccessToken != "login-at" {
					t.Fatalf("Acquire token = %+v, want the signed-in token", token)
				}
				if !strings.HasPrefix(auth.req.AuthorizationEndpoint, srv.URL) {
					t.Errorf("signed in against %q, want the discovered endpoint", auth.req.AuthorizationEndpoint)
				}
				return
			}

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Acquire error = %v, want %v", err, tt.wantErr)
			}
			other := ErrDiscovery
			if tt.wantErr == ErrDiscovery {
				other = ErrNotOAuthHost
			}
			if errors.Is(err, other) {
				t.Errorf("Acquire error %v is both ErrNotOAuthHost and ErrDiscovery", err)
			}
			if auth.calls != 0 {
				t.Errorf("signed in after a discovery failure")
			}
		})
	}
}
