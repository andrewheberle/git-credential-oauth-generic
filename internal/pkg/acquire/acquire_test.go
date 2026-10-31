package acquire

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

const callbackPort = 8400

// fakeAS is an httptest authorization server that is also the protected
// resource, so the resource URL and the AS URL are both its URL.
type fakeAS struct {
	*httptest.Server

	noDiscovery    bool // .well-known documents return 404
	noRegistration bool // metadata omits registration_endpoint
	validRefresh   string

	mu               sync.Mutex
	requests         []string // request paths, in order
	registerRedirect string
}

func newFakeAS(t *testing.T) *fakeAS {
	t.Helper()
	as := &fakeAS{validRefresh: "good-rt"}
	as.Server = httptest.NewServer(http.HandlerFunc(as.serve))
	t.Cleanup(as.Close)
	return as
}

func (as *fakeAS) serve(w http.ResponseWriter, r *http.Request) {
	as.mu.Lock()
	as.requests = append(as.requests, r.URL.Path)
	as.mu.Unlock()

	switch r.URL.Path {
	case "/.well-known/oauth-protected-resource":
		if as.noDiscovery {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"authorization_servers": []string{as.URL}})

	case "/.well-known/oauth-authorization-server":
		meta := map[string]any{
			"issuer":                 as.URL,
			"authorization_endpoint": as.URL + "/authorize",
			"token_endpoint":         as.URL + "/token",
			"scopes_supported":       []string{"git"},
		}
		if !as.noRegistration {
			meta["registration_endpoint"] = as.URL + "/register"
		}
		writeJSON(w, http.StatusOK, meta)

	case "/register":
		var req struct {
			RedirectURIs []string `json:"redirect_uris"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		as.mu.Lock()
		if len(req.RedirectURIs) > 0 {
			as.registerRedirect = req.RedirectURIs[0]
		}
		as.mu.Unlock()
		writeJSON(w, http.StatusCreated, map[string]any{"client_id": "registered-id", "client_secret": "registered-secret"})

	case "/token":
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != as.validRefresh {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token":  "refreshed-at",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "refreshed-rt",
		})

	default:
		http.NotFound(w, r)
	}
}

func (as *fakeAS) hits(path string) int {
	as.mu.Lock()
	defer as.mu.Unlock()
	n := 0
	for _, p := range as.requests {
		if p == path {
			n++
		}
	}
	return n
}

func (as *fakeAS) totalHits() int {
	as.mu.Lock()
	defer as.mu.Unlock()
	return len(as.requests)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// fakeCache is an in-memory TokenCache.
type fakeCache struct {
	mu      sync.Mutex
	tokens  map[string]*oauth2.Token
	saveErr error
	erased  int
}

func newFakeCache() *fakeCache { return &fakeCache{tokens: map[string]*oauth2.Token{}} }

func (c *fakeCache) Load(_ context.Context, resourceURL string) (*oauth2.Token, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tokens[resourceURL], nil
}

func (c *fakeCache) Save(_ context.Context, resourceURL string, token *oauth2.Token) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.saveErr != nil {
		return c.saveErr
	}
	c.tokens[resourceURL] = token
	return nil
}

func (c *fakeCache) Erase(_ context.Context, resourceURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.tokens, resourceURL)
	c.erased++
}

// fakeRegistry is an in-memory ClientRegistry.
type fakeRegistry struct {
	mu          sync.Mutex
	clients     map[string]Client
	lookupErr   error
	rememberErr error
}

func newFakeRegistry() *fakeRegistry { return &fakeRegistry{clients: map[string]Client{}} }

func (r *fakeRegistry) Lookup(_ context.Context, resourceURL string) (Client, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.lookupErr != nil {
		return Client{}, r.lookupErr
	}
	return r.clients[resourceURL], nil
}

func (r *fakeRegistry) Remember(_ context.Context, resourceURL string, client Client) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rememberErr != nil {
		return r.rememberErr
	}
	r.clients[resourceURL] = client
	return nil
}

// fakeAuthorizer records the configuration it was called with.
type fakeAuthorizer struct {
	token *oauth2.Token
	err   error

	calls int
	cfg   oauth2.Config
}

func (f *fakeAuthorizer) authorize(_ context.Context, cfg oauth2.Config, _ string) (*oauth2.Token, error) {
	f.calls++
	f.cfg = cfg
	return f.token, f.err
}

func validToken(access string) *oauth2.Token {
	return &oauth2.Token{AccessToken: access, RefreshToken: access + "-rt", Expiry: time.Now().Add(time.Hour)}
}

func TestAcquire(t *testing.T) {
	loginFailed := errors.New("user closed the browser")
	registryUnreadable := errors.New("git config unreadable")

	tests := []struct {
		name string
		// setup prepares the fakes; resourceURL is the fake AS's URL.
		setup func(as *fakeAS, cache *fakeCache, reg *fakeRegistry, auth *fakeAuthorizer, resourceURL string)

		wantAccess  string
		wantErr     error // matched with errors.Is; nil means success
		wantErrText string
		wantWarn    string // substring of a warning that must be logged
		check       func(t *testing.T, as *fakeAS, cache *fakeCache, reg *fakeRegistry, auth *fakeAuthorizer, resourceURL string)
	}{
		{
			name: "valid cached token makes no HTTP requests",
			setup: func(as *fakeAS, cache *fakeCache, reg *fakeRegistry, auth *fakeAuthorizer, res string) {
				cache.tokens[res] = validToken("cached-at")
			},
			wantAccess: "cached-at",
			check: func(t *testing.T, as *fakeAS, cache *fakeCache, reg *fakeRegistry, auth *fakeAuthorizer, res string) {
				if n := as.totalHits(); n != 0 {
					t.Errorf("made %d HTTP requests, want 0", n)
				}
				if auth.calls != 0 {
					t.Errorf("authorizer called %d times, want 0", auth.calls)
				}
			},
		},
		{
			name: "expired token is refreshed and saved",
			setup: func(as *fakeAS, cache *fakeCache, reg *fakeRegistry, auth *fakeAuthorizer, res string) {
				cache.tokens[res] = &oauth2.Token{AccessToken: "old-at", RefreshToken: "good-rt", Expiry: time.Now().Add(-time.Hour)}
				reg.clients[res] = Client{ID: "known-id"}
			},
			wantAccess: "refreshed-at",
			check: func(t *testing.T, as *fakeAS, cache *fakeCache, reg *fakeRegistry, auth *fakeAuthorizer, res string) {
				if got := cache.tokens[res]; got == nil || got.AccessToken != "refreshed-at" || got.RefreshToken != "refreshed-rt" {
					t.Errorf("cache holds %+v, want the refreshed token", got)
				}
				if auth.calls != 0 {
					t.Errorf("authorizer called %d times, want 0", auth.calls)
				}
			},
		},
		{
			name: "failed refresh erases the cache and falls back to login",
			setup: func(as *fakeAS, cache *fakeCache, reg *fakeRegistry, auth *fakeAuthorizer, res string) {
				cache.tokens[res] = &oauth2.Token{AccessToken: "old-at", RefreshToken: "revoked-rt", Expiry: time.Now().Add(-time.Hour)}
				reg.clients[res] = Client{ID: "known-id"}
				auth.token = validToken("login-at")
			},
			wantAccess: "login-at",
			check: func(t *testing.T, as *fakeAS, cache *fakeCache, reg *fakeRegistry, auth *fakeAuthorizer, res string) {
				if cache.erased != 1 {
					t.Errorf("cache erased %d times, want 1", cache.erased)
				}
				if as.hits("/register") != 0 {
					t.Error("registered a new client although one was known")
				}
				if got := cache.tokens[res]; got == nil || got.AccessToken != "login-at" {
					t.Errorf("cache holds %+v, want the login token", got)
				}
			},
		},
		{
			name: "no refresh without a registered client",
			setup: func(as *fakeAS, cache *fakeCache, reg *fakeRegistry, auth *fakeAuthorizer, res string) {
				cache.tokens[res] = &oauth2.Token{AccessToken: "old-at", RefreshToken: "good-rt", Expiry: time.Now().Add(-time.Hour)}
				auth.token = validToken("login-at")
			},
			wantAccess: "login-at",
			check: func(t *testing.T, as *fakeAS, cache *fakeCache, reg *fakeRegistry, auth *fakeAuthorizer, res string) {
				if n := as.hits("/token"); n != 0 {
					t.Errorf("token endpoint called %d times, want 0", n)
				}
			},
		},
		{
			name: "no client registers, remembers it and logs in with it",
			setup: func(as *fakeAS, cache *fakeCache, reg *fakeRegistry, auth *fakeAuthorizer, res string) {
				auth.token = validToken("login-at")
			},
			wantAccess: "login-at",
			check: func(t *testing.T, as *fakeAS, cache *fakeCache, reg *fakeRegistry, auth *fakeAuthorizer, res string) {
				want := Client{ID: "registered-id", Secret: "registered-secret", RedirectURI: "http://localhost:8400/callback"}
				if got := reg.clients[res]; got != want {
					t.Errorf("registry holds %+v, want %+v", got, want)
				}
				wantRedirect := "http://localhost:8400/callback"
				if as.registerRedirect != wantRedirect {
					t.Errorf("registered redirect URI %q, want %q", as.registerRedirect, wantRedirect)
				}
				cfg := auth.cfg
				if cfg.ClientID != want.ID || cfg.ClientSecret != want.Secret {
					t.Errorf("authorizer got client %q/%q, want %q/%q", cfg.ClientID, cfg.ClientSecret, want.ID, want.Secret)
				}
				if cfg.RedirectURL != wantRedirect {
					t.Errorf("authorizer got redirect %q, want %q", cfg.RedirectURL, wantRedirect)
				}
				if cfg.Endpoint.AuthURL != as.URL+"/authorize" || cfg.Endpoint.TokenURL != as.URL+"/token" {
					t.Errorf("authorizer got endpoints %+v", cfg.Endpoint)
				}
				if len(cfg.Scopes) != 1 || cfg.Scopes[0] != "git" {
					t.Errorf("authorizer got scopes %v, want [git]", cfg.Scopes)
				}
			},
		},
		{
			name: "no client and no registration endpoint",
			setup: func(as *fakeAS, cache *fakeCache, reg *fakeRegistry, auth *fakeAuthorizer, res string) {
				as.noRegistration = true
			},
			wantErr: ErrClientIDRequired,
			check: func(t *testing.T, as *fakeAS, cache *fakeCache, reg *fakeRegistry, auth *fakeAuthorizer, res string) {
				if auth.calls != 0 {
					t.Errorf("authorizer called %d times, want 0", auth.calls)
				}
			},
		},
		{
			name: "host without OAuth metadata",
			setup: func(as *fakeAS, cache *fakeCache, reg *fakeRegistry, auth *fakeAuthorizer, res string) {
				as.noDiscovery = true
			},
			wantErr: ErrNotOAuthHost,
		},
		{
			name: "failed login is an error",
			setup: func(as *fakeAS, cache *fakeCache, reg *fakeRegistry, auth *fakeAuthorizer, res string) {
				reg.clients[res] = Client{ID: "known-id"}
				auth.err = loginFailed
			},
			wantErr: loginFailed,
			check: func(t *testing.T, as *fakeAS, cache *fakeCache, reg *fakeRegistry, auth *fakeAuthorizer, res string) {
				if len(cache.tokens) != 0 {
					t.Errorf("cache holds %v after a failed login", cache.tokens)
				}
			},
		},
		{
			name: "unreadable client registry stops without registering",
			setup: func(as *fakeAS, cache *fakeCache, reg *fakeRegistry, auth *fakeAuthorizer, res string) {
				reg.lookupErr = registryUnreadable
			},
			wantErr: registryUnreadable,
			check: func(t *testing.T, as *fakeAS, cache *fakeCache, reg *fakeRegistry, auth *fakeAuthorizer, res string) {
				if as.hits("/register") != 0 || auth.calls != 0 {
					t.Errorf("registered %d times and signed in %d times after a lookup error, want 0 and 0", as.hits("/register"), auth.calls)
				}
			},
		},
		{
			name: "changed redirect URI registers a new client",
			setup: func(as *fakeAS, cache *fakeCache, reg *fakeRegistry, auth *fakeAuthorizer, res string) {
				reg.clients[res] = Client{ID: "old-id", RedirectURI: "http://localhost:9999/callback"}
				auth.token = validToken("login-at")
			},
			wantAccess: "login-at",
			check: func(t *testing.T, as *fakeAS, cache *fakeCache, reg *fakeRegistry, auth *fakeAuthorizer, res string) {
				if as.hits("/register") != 1 || auth.cfg.ClientID != "registered-id" {
					t.Errorf("registrations=%d, signed in as %q; want 1 and registered-id", as.hits("/register"), auth.cfg.ClientID)
				}
				if got := reg.clients[res].RedirectURI; got != "http://localhost:8400/callback" {
					t.Errorf("remembered redirect URI %q, want the current one", got)
				}
			},
		},
		{
			name: "client without a recorded redirect URI is never replaced",
			setup: func(as *fakeAS, cache *fakeCache, reg *fakeRegistry, auth *fakeAuthorizer, res string) {
				reg.clients[res] = Client{ID: "by-hand"}
				auth.token = validToken("login-at")
			},
			wantAccess: "login-at",
			check: func(t *testing.T, as *fakeAS, cache *fakeCache, reg *fakeRegistry, auth *fakeAuthorizer, res string) {
				if as.hits("/register") != 0 || auth.cfg.ClientID != "by-hand" {
					t.Errorf("registrations=%d, signed in as %q; want 0 and by-hand", as.hits("/register"), auth.cfg.ClientID)
				}
			},
		},
		{
			name: "changed redirect URI without a registration endpoint keeps the client and warns",
			setup: func(as *fakeAS, cache *fakeCache, reg *fakeRegistry, auth *fakeAuthorizer, res string) {
				as.noRegistration = true
				reg.clients[res] = Client{ID: "old-id", RedirectURI: "http://localhost:9999/callback"}
				auth.token = validToken("login-at")
			},
			wantAccess: "login-at",
			wantWarn:   "different redirect URI",
			check: func(t *testing.T, as *fakeAS, cache *fakeCache, reg *fakeRegistry, auth *fakeAuthorizer, res string) {
				if auth.cfg.ClientID != "old-id" {
					t.Errorf("signed in as %q, want old-id", auth.cfg.ClientID)
				}
			},
		},
		{
			name: "failure to remember a new client warns and still signs in",
			setup: func(as *fakeAS, cache *fakeCache, reg *fakeRegistry, auth *fakeAuthorizer, res string) {
				reg.rememberErr = errors.New("no keyring")
				auth.token = validToken("login-at")
			},
			wantAccess: "login-at",
			wantWarn:   "could not save registered client",
		},
		{
			name: "failed save warns and still returns the token",
			setup: func(as *fakeAS, cache *fakeCache, reg *fakeRegistry, auth *fakeAuthorizer, res string) {
				reg.clients[res] = Client{ID: "known-id"}
				auth.token = validToken("login-at")
				cache.saveErr = errors.New("keyring locked")
			},
			wantAccess: "login-at",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			as := newFakeAS(t)
			cache := newFakeCache()
			reg := newFakeRegistry()
			auth := &fakeAuthorizer{}
			resourceURL := as.URL
			tt.setup(as, cache, reg, auth, resourceURL)

			var logs bytes.Buffer
			a := New(Config{
				Cache:        cache,
				Clients:      reg,
				Authorize:    auth.authorize,
				HTTPClient:   as.Client(),
				CallbackPort: callbackPort,
				Logger:       slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})),
			})

			token, err := a.Acquire(context.Background(), resourceURL)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Acquire: got error %v, want %v", err, tt.wantErr)
				}
			} else {
				if err != nil {
					t.Fatalf("Acquire: unexpected error: %v", err)
				}
				if token == nil || token.AccessToken != tt.wantAccess {
					t.Fatalf("Acquire: got token %+v, want access token %q", token, tt.wantAccess)
				}
			}

			if tt.wantWarn != "" && !strings.Contains(logs.String(), tt.wantWarn) {
				t.Errorf("expected a warning containing %q, got logs: %q", tt.wantWarn, logs.String())
			}
			if cache.saveErr != nil && !strings.Contains(logs.String(), "could not save tokens") {
				t.Errorf("expected a save warning, got logs: %q", logs.String())
			}

			if tt.check != nil {
				tt.check(t, as, cache, reg, auth, resourceURL)
			}
		})
	}
}

func TestNewDefaults(t *testing.T) {
	a := New(Config{})
	if a.httpClient == nil || a.httpClient.Timeout != defaultHTTPTimeout {
		t.Errorf("default HTTP client = %+v, want timeout %v", a.httpClient, defaultHTTPTimeout)
	}
	if a.logger == nil {
		t.Error("default logger is nil")
	}
}
