package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andrewheberle/git-credential-oauth-generic/internal/pkg/acquire"
	"golang.org/x/oauth2"
)

// memCache is an in-memory Token cache that counts reads and writes.
type memCache struct {
	mu     sync.Mutex
	tokens map[string]*oauth2.Token
	loads  int
	saves  int
}

func newMemCache() *memCache { return &memCache{tokens: map[string]*oauth2.Token{}} }

func (c *memCache) Load(_ context.Context, resourceURL string) (*oauth2.Token, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loads++
	return c.tokens[resourceURL], nil
}

func (c *memCache) Save(_ context.Context, resourceURL string, token *oauth2.Token) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.saves++
	c.tokens[resourceURL] = token
	return nil
}

func (c *memCache) Erase(_ context.Context, resourceURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.tokens, resourceURL)
}

// memRegistry is an in-memory client registry.
type memRegistry struct {
	mu      sync.Mutex
	clients map[string]acquire.Client
}

func newMemRegistry() *memRegistry { return &memRegistry{clients: map[string]acquire.Client{}} }

func (r *memRegistry) Lookup(_ context.Context, resourceURL string) (acquire.Client, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.clients[resourceURL], nil
}

func (r *memRegistry) Remember(_ context.Context, resourceURL string, client acquire.Client) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clients[resourceURL] = client
	return nil
}

// fakeAuthorizer stands in for the browser sign-in.
type fakeAuthorizer struct {
	mu    sync.Mutex
	calls []acquire.AuthorizationRequest
}

func (f *fakeAuthorizer) authorize(_ context.Context, req acquire.AuthorizationRequest, _ acquire.Exchange) (*oauth2.Token, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, req)
	return &oauth2.Token{AccessToken: "signed-in-at", RefreshToken: "signed-in-rt", Expiry: time.Unix(2000000000, 0)}, nil
}

// gitRefreshToken is the refresh token the fake authorization server accepts.
const gitRefreshToken = "git-rt"

// newAuthServer is an httptest TLS server that is both the Git host and its
// authorization server, so a request for host=<its host> discovers itself.
// It counts every request it receives, and token endpoint requests
// separately. Its token endpoint only accepts refreshes of gitRefreshToken.
func newAuthServer(t *testing.T) (srv *httptest.Server, hits, tokenHits, registrations *int) {
	t.Helper()
	var mu sync.Mutex
	hits, tokenHits, registrations = new(int), new(int), new(int)
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		*hits++
		switch r.URL.Path {
		case "/token":
			*tokenHits++
		case "/register":
			*registrations++
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/oauth-protected-resource":
			_ = json.NewEncoder(w).Encode(map[string]any{"authorization_servers": []string{srv.URL}})
		case "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 srv.URL,
				"authorization_endpoint": srv.URL + "/authorize",
				"token_endpoint":         srv.URL + "/token",
				"registration_endpoint":  srv.URL + "/register",
			})
		case "/register":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"client_id": "registered-id"})
		case "/token":
			_ = r.ParseForm()
			if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != gitRefreshToken {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "refreshed-at", "token_type": "Bearer", "expires_in": 3600, "refresh_token": "refreshed-rt",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, hits, tokenHits, registrations
}

// fixture is one run's environment plus the fakes behind it.
type fixture struct {
	srv       *httptest.Server
	hits      *int
	tokenHits *int
	// registrations counts dynamic client registrations.
	registrations *int
	stdout        string // the last run's stdout
	host          string // the server's host, as Git would send it
	resource      string // its Resource URL
	cache         *memCache
	clients       *memRegistry
	authz         *fakeAuthorizer
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	srv, hits, tokenHits, registrations := newAuthServer(t)
	host := strings.TrimPrefix(srv.URL, "https://")
	return &fixture{
		srv: srv, hits: hits, tokenHits: tokenHits, registrations: registrations, host: host, resource: "https://" + host,
		cache: newMemCache(), clients: newMemRegistry(), authz: &fakeAuthorizer{},
	}
}

// run executes the helper with args and stdin, returning stdout and stderr.
func (f *fixture) run(t *testing.T, args []string, stdin string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errOut bytes.Buffer
	err = execute(context.Background(), args, env{
		stdin:      strings.NewReader(stdin),
		stdout:     &out,
		stderr:     &errOut,
		tokenCache: f.cache,
		clients:    f.clients,
		httpClient: f.srv.Client(),
		authorize:  f.authz.authorize,
	})
	f.stdout = out.String()
	return out.String(), errOut.String(), err
}

// withRefreshToken adds the oauth_refresh_token an earlier helper (such as
// git-credential-cache returning an expired credential) passes along.
func withRefreshToken(request, refreshToken string) string {
	return strings.TrimSuffix(request, "\n") + "oauth_refresh_token=" + refreshToken + "\n\n"
}

func (f *fixture) request(protocol string, capabilities ...string) string {
	var b strings.Builder
	for _, c := range capabilities {
		b.WriteString("capability[]=" + c + "\n")
	}
	b.WriteString("protocol=" + protocol + "\nhost=" + f.host + "\n\n")
	return b.String()
}

const signedInCredential = "capability[]=authtype\nauthtype=Bearer\ncredential=signed-in-at\npassword_expiry_utc=2000000000\noauth_refresh_token=signed-in-rt\n"

func TestCommands(t *testing.T) {
	validToken := func() *oauth2.Token {
		return &oauth2.Token{AccessToken: "cached-at", Expiry: time.Now().Add(time.Hour)}
	}

	tests := []struct {
		name  string
		args  []string
		stdin func(f *fixture) string
		setup func(f *fixture)

		wantErr    bool
		wantStdout func(f *fixture) string
		wantStderr string // substring
		check      func(t *testing.T, f *fixture)
	}{
		{
			name:       "capability",
			args:       []string{"capability"},
			wantStdout: func(*fixture) string { return "version 0\ncapability authtype\n" },
		},
		{
			name:  "get with a valid cached token makes no requests",
			args:  []string{"get"},
			stdin: func(f *fixture) string { return f.request("https", "authtype") },
			setup: func(f *fixture) { f.cache.tokens[f.resource] = validToken() },
			wantStdout: func(*fixture) string {
				return "capability[]=authtype\nauthtype=Bearer\ncredential=cached-at\npassword_expiry_utc="
			},
			check: func(t *testing.T, f *fixture) {
				if *f.hits != 0 {
					t.Errorf("made %d HTTP requests, want 0", *f.hits)
				}
				if len(f.authz.calls) != 0 {
					t.Errorf("signed in %d times, want 0", len(f.authz.calls))
				}
			},
		},
		{
			name:       "get runs the full flow and stores the results",
			args:       []string{"get"},
			stdin:      func(f *fixture) string { return f.request("https", "authtype") },
			wantStdout: func(*fixture) string { return signedInCredential },
			check: func(t *testing.T, f *fixture) {
				if got := f.cache.tokens[f.resource]; got == nil || got.AccessToken != "signed-in-at" {
					t.Errorf("cache holds %+v, want the signed-in token", got)
				}
				if got := f.clients.clients[f.resource].ID; got != "registered-id" {
					t.Errorf("registry holds client %q, want registered-id", got)
				}
				if len(f.authz.calls) != 1 || f.authz.calls[0].RedirectURI != "http://localhost:8400/callback" {
					t.Errorf("authorizer calls = %+v, want one with the default redirect URI", f.authz.calls)
				}
			},
		},
		{
			name:  "--port before the subcommand reaches the redirect URI",
			args:  []string{"--port", "9000", "get"},
			stdin: func(f *fixture) string { return f.request("https", "authtype") },
			setup: func(f *fixture) {
				f.clients.clients[f.resource] = acquire.Client{ID: "known-id"}
			},
			wantStdout: func(*fixture) string { return signedInCredential },
			check: func(t *testing.T, f *fixture) {
				if len(f.authz.calls) != 1 || f.authz.calls[0].RedirectURI != "http://localhost:9000/callback" {
					t.Errorf("authorizer calls = %+v, want one with port 9000", f.authz.calls)
				}
			},
		},
		{
			name:       "--nopersist leaves the token cache alone",
			args:       []string{"--nopersist", "get"},
			stdin:      func(f *fixture) string { return f.request("https", "authtype") },
			setup:      func(f *fixture) { f.cache.tokens[f.resource] = validToken() },
			wantStdout: func(*fixture) string { return signedInCredential },
			check: func(t *testing.T, f *fixture) {
				if f.cache.loads != 0 || f.cache.saves != 0 {
					t.Errorf("cache loads=%d saves=%d, want 0 and 0", f.cache.loads, f.cache.saves)
				}
			},
		},
		{
			// #46
			name:  "--nopersist refreshes with the token Git passed back",
			args:  []string{"--nopersist", "get"},
			stdin: func(f *fixture) string { return withRefreshToken(f.request("https", "authtype"), gitRefreshToken) },
			setup: func(f *fixture) { f.clients.clients[f.resource] = acquire.Client{ID: "known-id"} },
			wantStdout: func(*fixture) string {
				return "capability[]=authtype\nauthtype=Bearer\ncredential=refreshed-at\npassword_expiry_utc="
			},
			check: func(t *testing.T, f *fixture) {
				if !strings.HasSuffix(f.stdout, "\noauth_refresh_token=refreshed-rt\n") {
					t.Errorf("stdout %q does not hand the new refresh token back to Git", f.stdout)
				}
				if len(f.authz.calls) != 0 {
					t.Errorf("signed in %d times, want 0", len(f.authz.calls))
				}
				if f.cache.loads != 0 || f.cache.saves != 0 {
					t.Errorf("persistent cache loads=%d saves=%d, want 0 and 0", f.cache.loads, f.cache.saves)
				}
			},
		},
		{
			name:       "--nopersist signs in when the passed-back refresh token is rejected",
			args:       []string{"--nopersist", "get"},
			stdin:      func(f *fixture) string { return withRefreshToken(f.request("https", "authtype"), "revoked-rt") },
			setup:      func(f *fixture) { f.clients.clients[f.resource] = acquire.Client{ID: "known-id"} },
			wantStdout: func(*fixture) string { return signedInCredential },
			check: func(t *testing.T, f *fixture) {
				if *f.tokenHits != 1 || len(f.authz.calls) != 1 {
					t.Errorf("token endpoint hits=%d sign-ins=%d, want 1 and 1", *f.tokenHits, len(f.authz.calls))
				}
			},
		},
		{
			name:       "--nopersist signs in when no client is registered to refresh with",
			args:       []string{"--nopersist", "get"},
			stdin:      func(f *fixture) string { return withRefreshToken(f.request("https", "authtype"), gitRefreshToken) },
			wantStdout: func(*fixture) string { return signedInCredential },
			check: func(t *testing.T, f *fixture) {
				if *f.tokenHits != 0 || len(f.authz.calls) != 1 {
					t.Errorf("token endpoint hits=%d sign-ins=%d, want 0 and 1", *f.tokenHits, len(f.authz.calls))
				}
			},
		},
		{
			name:       "without --nopersist a passed-back refresh token is ignored",
			args:       []string{"get"},
			stdin:      func(f *fixture) string { return withRefreshToken(f.request("https", "authtype"), gitRefreshToken) },
			setup:      func(f *fixture) { f.clients.clients[f.resource] = acquire.Client{ID: "known-id"} },
			wantStdout: func(*fixture) string { return signedInCredential },
			check: func(t *testing.T, f *fixture) {
				if *f.tokenHits != 0 || len(f.authz.calls) != 1 {
					t.Errorf("token endpoint hits=%d sign-ins=%d, want 0 and 1", *f.tokenHits, len(f.authz.calls))
				}
			},
		},
		{
			// #53
			name:       "get declines http",
			args:       []string{"get"},
			stdin:      func(f *fixture) string { return f.request("http", "authtype") },
			wantStdout: func(*fixture) string { return "" },
			check:      assertNoWork,
		},
		{
			// #44
			name:       "get declines Git without authtype before any work",
			args:       []string{"get"},
			stdin:      func(f *fixture) string { return f.request("https") },
			wantStdout: func(*fixture) string { return "" },
			wantStderr: "requires Git 2.45+",
			check:      assertNoWork,
		},
		{
			name:       "get declines a request without a host",
			args:       []string{"get"},
			stdin:      func(*fixture) string { return "capability[]=authtype\nprotocol=https\n\n" },
			wantStdout: func(*fixture) string { return "" },
			check:      assertNoWork,
		},
		{
			name:  "erase removes the cached token",
			args:  []string{"erase"},
			stdin: func(f *fixture) string { return f.request("https") },
			setup: func(f *fixture) { f.cache.tokens[f.resource] = validToken() },
			check: func(t *testing.T, f *fixture) {
				if _, ok := f.cache.tokens[f.resource]; ok {
					t.Error("cached token survived erase")
				}
			},
		},
		{
			name:  "erase ignores http",
			args:  []string{"erase"},
			stdin: func(f *fixture) string { return f.request("http") },
			setup: func(f *fixture) { f.cache.tokens[f.resource] = validToken() },
			check: assertCacheKept,
		},
		{
			name:  "erase with --nopersist leaves the token cache alone",
			args:  []string{"--nopersist", "erase"},
			stdin: func(f *fixture) string { return f.request("https") },
			setup: func(f *fixture) { f.cache.tokens[f.resource] = validToken() },
			check: assertCacheKept,
		},
		{
			name:       "no subcommand is an error with usage on stderr",
			args:       []string{},
			wantErr:    true,
			wantStdout: func(*fixture) string { return "" },
			wantStderr: "Usage:",
		},
		{
			name:       "help goes to stdout",
			args:       []string{"--help"},
			wantStdout: func(*fixture) string { return "A Git credential helper" },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			if tt.setup != nil {
				tt.setup(f)
			}
			stdin := ""
			if tt.stdin != nil {
				stdin = tt.stdin(f)
			}

			stdout, stderr, err := f.run(t, tt.args, stdin)

			if (err != nil) != tt.wantErr {
				t.Fatalf("execute error = %v, wantErr %v (stderr %q)", err, tt.wantErr, stderr)
			}
			if tt.wantStdout != nil {
				want := tt.wantStdout(f)
				// A cached token's expiry varies, so its expected output is a prefix.
				if !strings.HasPrefix(stdout, want) || (want == "" && stdout != "") {
					t.Errorf("stdout = %q, want %q", stdout, want)
				}
			}
			if tt.wantStderr != "" && !strings.Contains(stderr, tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr, tt.wantStderr)
			}
			if tt.check != nil {
				tt.check(t, f)
			}
		})
	}
}

func assertNoWork(t *testing.T, f *fixture) {
	t.Helper()
	if *f.hits != 0 || len(f.authz.calls) != 0 || f.cache.loads != 0 {
		t.Errorf("did work for a declined request: %d HTTP requests, %d sign-ins, %d cache loads",
			*f.hits, len(f.authz.calls), f.cache.loads)
	}
}

func assertCacheKept(t *testing.T, f *fixture) {
	t.Helper()
	if _, ok := f.cache.tokens[f.resource]; !ok {
		t.Error("cached token was erased")
	}
}

func TestGetDiscoveryOutcomes(t *testing.T) {
	tests := []struct {
		name string
		// asMeta is the status of the authorization server metadata; the
		// protected resource metadata is served only when it is non-zero.
		asMeta  int
		wantErr error
	}{
		{name: "non-OAuth host is declined silently", asMeta: 0},
		{name: "authorization server outage is reported", asMeta: http.StatusServiceUnavailable, wantErr: acquire.ErrDiscovery},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var srv *httptest.Server
			srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case tt.asMeta != 0 && r.URL.Path == "/.well-known/oauth-protected-resource":
					_ = json.NewEncoder(w).Encode(map[string]any{"resource": srv.URL, "authorization_servers": []string{srv.URL}})
				case tt.asMeta != 0 && r.URL.Path == "/.well-known/oauth-authorization-server":
					w.WriteHeader(tt.asMeta)
				default:
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(srv.Close)

			authz := &fakeAuthorizer{}
			var out, errOut bytes.Buffer
			err := execute(context.Background(), []string{"get"}, env{
				stdin:      strings.NewReader("capability[]=authtype\nprotocol=https\nhost=" + strings.TrimPrefix(srv.URL, "https://") + "\n\n"),
				stdout:     &out,
				stderr:     &errOut,
				tokenCache: newMemCache(),
				clients:    newMemRegistry(),
				httpClient: srv.Client(),
				authorize:  authz.authorize,
			})

			if tt.wantErr == nil && err != nil {
				t.Fatalf("execute error = %v, want a silent decline", err)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("execute error = %v, want %v", err, tt.wantErr)
			}
			if out.Len() != 0 || len(authz.calls) != 0 {
				t.Errorf("stdout %q, %d sign-ins; want no credential and no sign-in", out.String(), len(authz.calls))
			}
			if tt.wantErr == nil && errOut.Len() != 0 {
				t.Errorf("stderr %q, want nothing for a non-OAuth host", errOut.String())
			}
		})
	}
}

// A host that publishes its metadata only at the resource_metadata URL in
// its WWW-Authenticate challenge is still found: the hint in Git's
// wwwauth[] reaches discovery.
func TestGetFollowsResourceMetadataHint(t *testing.T) {
	const hintPath = "/.well-known/cloudflare-access-protected-resource/info/refs"
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case hintPath:
			_ = json.NewEncoder(w).Encode(map[string]any{"resource": srv.URL + "/info/refs", "authorization_servers": []string{srv.URL}})
		case "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 srv.URL,
				"authorization_endpoint": srv.URL + "/authorize",
				"token_endpoint":         srv.URL + "/token",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	host := strings.TrimPrefix(srv.URL, "https://")
	clients := newMemRegistry()
	clients.clients[srv.URL] = acquire.Client{ID: "known-id"}
	authz := &fakeAuthorizer{}

	var out, errOut bytes.Buffer
	err := execute(context.Background(), []string{"get"}, env{
		stdin: strings.NewReader("capability[]=authtype\nprotocol=https\nhost=" + host + "\n" +
			`wwwauth[]=Bearer realm="OAuth", error="invalid_token", error_description="Missing or invalid access token", resource_metadata="` + srv.URL + hintPath + `"` + "\n\n"),
		stdout:     &out,
		stderr:     &errOut,
		tokenCache: newMemCache(),
		clients:    clients,
		httpClient: srv.Client(),
		authorize:  authz.authorize,
	})
	if err != nil {
		t.Fatalf("execute: %v (stderr %q)", err, errOut.String())
	}
	if out.String() != signedInCredential {
		t.Errorf("stdout = %q, want the signed-in credential", out.String())
	}
	if len(authz.calls) != 1 || authz.calls[0].Resource != srv.URL {
		t.Errorf("sign-ins = %+v, want one for the host-wide resource %q", authz.calls, srv.URL)
	}
}
