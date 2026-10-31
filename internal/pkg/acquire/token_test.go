package acquire

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// tokenRequest is one request the token server received.
type tokenRequest struct {
	form     url.Values
	user     string
	pass     string
	hasBasic bool
}

// tokenServer is an httptest server that is a Git host, its authorization
// server and its token endpoint, and records every token request.
type tokenServer struct {
	*httptest.Server

	authMethods []string // token_endpoint_auth_methods_supported; nil omits it
	issueSecret bool     // registration issues a client secret

	tokenStatus int    // 0 means 200
	tokenBody   string // "" means a valid Bearer token response
	tokenDelay  time.Duration

	mu           sync.Mutex
	tokenReqs    []tokenRequest
	registration map[string]any
}

func newTokenServer(t *testing.T, setup func(*tokenServer)) *tokenServer {
	t.Helper()
	ts := &tokenServer{}
	if setup != nil {
		setup(ts)
	}
	ts.Server = httptest.NewServer(http.HandlerFunc(ts.serve))
	t.Cleanup(ts.Close)
	return ts
}

func (ts *tokenServer) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/oauth-protected-resource":
		writeJSON(w, http.StatusOK, map[string]any{"resource": ts.URL, "authorization_servers": []string{ts.URL}})

	case "/.well-known/oauth-authorization-server":
		meta := map[string]any{
			"issuer":                 ts.URL,
			"authorization_endpoint": ts.URL + "/authorize",
			"token_endpoint":         ts.URL + "/token",
			"registration_endpoint":  ts.URL + "/register",
		}
		if ts.authMethods != nil {
			meta["token_endpoint_auth_methods_supported"] = ts.authMethods
		}
		writeJSON(w, http.StatusOK, meta)

	case "/register":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		ts.mu.Lock()
		ts.registration = body
		ts.mu.Unlock()
		client := map[string]any{"client_id": "registered-id"}
		if ts.issueSecret {
			client["client_secret"] = "registered-secret"
		}
		writeJSON(w, http.StatusCreated, client)

	case "/token":
		_ = r.ParseForm()
		user, pass, hasBasic := r.BasicAuth()
		ts.mu.Lock()
		ts.tokenReqs = append(ts.tokenReqs, tokenRequest{form: r.PostForm, user: user, pass: pass, hasBasic: hasBasic})
		ts.mu.Unlock()

		if ts.tokenDelay > 0 {
			select {
			case <-time.After(ts.tokenDelay):
			case <-r.Context().Done():
				return
			}
		}
		status, body := ts.tokenStatus, ts.tokenBody
		if status == 0 {
			status = http.StatusOK
		}
		if body == "" {
			body = `{"access_token":"new-at","token_type":"Bearer","expires_in":3600}`
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))

	default:
		http.NotFound(w, r)
	}
}

func (ts *tokenServer) requests() []tokenRequest {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return slices.Clone(ts.tokenReqs)
}

// expiredWithRefresh is a cached token that must be refreshed.
func expiredWithRefresh() *oauth2.Token {
	return &oauth2.Token{AccessToken: "old-at", RefreshToken: "old-rt", Expiry: time.Now().Add(-time.Hour)}
}

func TestTokenEndpoint(t *testing.T) {
	public := Client{ID: "public-id"}
	confidential := Client{ID: "conf id", Secret: "s3cr:et"} // characters RFC 6749 §2.3.1 encodes

	tests := []struct {
		name   string
		server func(*tokenServer)
		cached *oauth2.Token
		client Client // registered client; zero means none
		code   string // authorization code the fake Authorizer returns

		wantAccess string
		wantErr    bool
		check      func(t *testing.T, ts *tokenServer, cache *fakeCache, auth *fakeAuthorizer, res string)
	}{
		{
			name:       "refresh sends resource and authenticates a public client by client_id",
			cached:     expiredWithRefresh(),
			client:     public,
			wantAccess: "new-at",
			check: func(t *testing.T, ts *tokenServer, cache *fakeCache, auth *fakeAuthorizer, res string) {
				req := onlyRequest(t, ts)
				wantForm(t, req, map[string]string{"grant_type": "refresh_token", "refresh_token": "old-rt", "resource": res, "client_id": "public-id"})
				if req.hasBasic || req.form.Has("client_secret") {
					t.Errorf("public client sent credentials: basic=%v form=%v", req.hasBasic, req.form)
				}
				// The response had no refresh_token: the old one stays valid.
				if got := cache.tokens[res]; got == nil || got.AccessToken != "new-at" || got.RefreshToken != "old-rt" {
					t.Errorf("cache holds %+v, want new-at with old-rt kept", got)
				}
			},
		},
		{
			name:       "confidential client uses Basic when the server lists nothing",
			cached:     expiredWithRefresh(),
			client:     confidential,
			wantAccess: "new-at",
			check: func(t *testing.T, ts *tokenServer, cache *fakeCache, auth *fakeAuthorizer, res string) {
				req := onlyRequest(t, ts)
				if !req.hasBasic || req.user != url.QueryEscape("conf id") || req.pass != url.QueryEscape("s3cr:et") {
					t.Errorf("Basic auth = %v %q:%q, want form-encoded client credentials", req.hasBasic, req.user, req.pass)
				}
				if req.form.Has("client_secret") || req.form.Has("client_id") {
					t.Errorf("Basic auth request also sent credentials in the form: %v", req.form)
				}
			},
		},
		{
			name:       "confidential client uses Basic when listed",
			server:     func(ts *tokenServer) { ts.authMethods = []string{"client_secret_post", "client_secret_basic"} },
			cached:     expiredWithRefresh(),
			client:     confidential,
			wantAccess: "new-at",
			check: func(t *testing.T, ts *tokenServer, cache *fakeCache, auth *fakeAuthorizer, res string) {
				if req := onlyRequest(t, ts); !req.hasBasic {
					t.Error("did not use Basic auth although it is listed")
				}
			},
		},
		{
			name:       "confidential client posts its secret when only post is listed",
			server:     func(ts *tokenServer) { ts.authMethods = []string{"client_secret_post"} },
			cached:     expiredWithRefresh(),
			client:     confidential,
			wantAccess: "new-at",
			check: func(t *testing.T, ts *tokenServer, cache *fakeCache, auth *fakeAuthorizer, res string) {
				req := onlyRequest(t, ts)
				wantForm(t, req, map[string]string{"client_id": "conf id", "client_secret": "s3cr:et"})
				if req.hasBasic {
					t.Error("used Basic auth although only client_secret_post is listed")
				}
			},
		},
		{
			name: "rejected refresh token erases the cache and signs in",
			server: func(ts *tokenServer) {
				ts.tokenStatus = http.StatusBadRequest
				ts.tokenBody = `{"error":"invalid_grant","error_description":"refresh token expired"}`
			},
			cached:     expiredWithRefresh(),
			client:     public,
			wantAccess: "login-at",
			check: func(t *testing.T, ts *tokenServer, cache *fakeCache, auth *fakeAuthorizer, res string) {
				if cache.erased != 1 || auth.calls != 1 {
					t.Errorf("erased %d times, signed in %d times; want 1 and 1", cache.erased, auth.calls)
				}
			},
		},
		{
			name:    "token endpoint outage keeps the refresh token",
			server:  func(ts *tokenServer) { ts.tokenStatus = http.StatusServiceUnavailable; ts.tokenBody = "busy" },
			cached:  expiredWithRefresh(),
			client:  public,
			wantErr: true,
			check:   assertRefreshKept,
		},
		{
			name:    "token endpoint timeout keeps the refresh token",
			server:  func(ts *tokenServer) { ts.tokenDelay = time.Second },
			cached:  expiredWithRefresh(),
			client:  public,
			wantErr: true,
			check:   assertRefreshKept,
		},
		{
			name:    "a 4xx that isn't an OAuth error keeps the refresh token",
			server:  func(ts *tokenServer) { ts.tokenStatus = http.StatusForbidden; ts.tokenBody = "<html>blocked</html>" },
			cached:  expiredWithRefresh(),
			client:  public,
			wantErr: true,
			check:   assertRefreshKept,
		},
		{
			name:    "non-Bearer token is rejected",
			server:  func(ts *tokenServer) { ts.tokenBody = `{"access_token":"x","token_type":"mac"}` },
			cached:  expiredWithRefresh(),
			client:  public,
			wantErr: true,
			check:   assertRefreshKept,
		},
		{
			name: "expires_in sent as a string is accepted",
			server: func(ts *tokenServer) {
				ts.tokenBody = `{"access_token":"new-at","token_type":"bearer","expires_in":"3600","refresh_token":"new-rt"}`
			},
			cached:     expiredWithRefresh(),
			client:     public,
			wantAccess: "new-at",
			check: func(t *testing.T, ts *tokenServer, cache *fakeCache, auth *fakeAuthorizer, res string) {
				got := cache.tokens[res]
				if got == nil || got.RefreshToken != "new-rt" || time.Until(got.Expiry) < 59*time.Minute {
					t.Errorf("cache holds %+v, want new-rt expiring in about an hour", got)
				}
			},
		},
		{
			name:       "code exchange the Authorizer is given makes a correct request",
			server:     func(ts *tokenServer) { ts.authMethods = []string{"client_secret_basic"} },
			client:     confidential,
			code:       "the-code",
			wantAccess: "new-at",
			check: func(t *testing.T, ts *tokenServer, cache *fakeCache, auth *fakeAuthorizer, res string) {
				req := onlyRequest(t, ts)
				wantForm(t, req, map[string]string{
					"grant_type":    "authorization_code",
					"code":          "the-code",
					"code_verifier": "the-verifier",
					"redirect_uri":  "http://localhost:8400/callback",
					"resource":      res,
				})
				if !req.hasBasic {
					t.Error("code exchange did not authenticate the confidential client")
				}
			},
		},
		{
			name:       "registration asks to be a public client when none is listed",
			server:     func(ts *tokenServer) { ts.authMethods = []string{"client_secret_basic", "none"} },
			code:       "the-code",
			wantAccess: "new-at",
			check: func(t *testing.T, ts *tokenServer, cache *fakeCache, auth *fakeAuthorizer, res string) {
				if got := ts.registration["token_endpoint_auth_method"]; got != "none" {
					t.Errorf("registration token_endpoint_auth_method = %v, want none", got)
				}
				req := onlyRequest(t, ts)
				if req.hasBasic || req.form.Get("client_id") != "registered-id" {
					t.Errorf("public client exchange: basic=%v form=%v", req.hasBasic, req.form)
				}
			},
		},
		{
			name:       "registration leaves the method to the server when none isn't listed",
			server:     func(ts *tokenServer) { ts.authMethods = []string{"client_secret_basic"}; ts.issueSecret = true },
			code:       "the-code",
			wantAccess: "new-at",
			check: func(t *testing.T, ts *tokenServer, cache *fakeCache, auth *fakeAuthorizer, res string) {
				if _, ok := ts.registration["token_endpoint_auth_method"]; ok {
					t.Errorf("registration asked for %v although none isn't listed", ts.registration["token_endpoint_auth_method"])
				}
				if req := onlyRequest(t, ts); !req.hasBasic || req.user != "registered-id" {
					t.Errorf("issued secret not used with Basic: %+v", req)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := newTokenServer(t, tt.server)
			res := ts.URL
			cache := newFakeCache()
			if tt.cached != nil {
				cache.tokens[res] = tt.cached
			}
			reg := newFakeRegistry()
			if tt.client.ID != "" {
				reg.clients[res] = tt.client
			}
			auth := &fakeAuthorizer{token: validToken("login-at"), code: tt.code, verifier: "the-verifier"}

			client := ts.Client()
			client.Timeout = 250 * time.Millisecond
			a := New(Config{Cache: cache, Clients: reg, Authorize: auth.authorize, HTTPClient: client, CallbackPort: callbackPort})

			token, err := a.Acquire(context.Background(), res, "")
			switch {
			case tt.wantErr && err == nil:
				t.Fatalf("Acquire: expected an error, got token %+v", token)
			case !tt.wantErr && err != nil:
				t.Fatalf("Acquire: unexpected error: %v", err)
			case !tt.wantErr && (token == nil || token.AccessToken != tt.wantAccess):
				t.Fatalf("Acquire token = %+v, want access token %q", token, tt.wantAccess)
			}
			if tt.check != nil {
				tt.check(t, ts, cache, auth, res)
			}
		})
	}
}

func onlyRequest(t *testing.T, ts *tokenServer) tokenRequest {
	t.Helper()
	reqs := ts.requests()
	if len(reqs) != 1 {
		t.Fatalf("token endpoint got %d requests, want 1", len(reqs))
	}
	return reqs[0]
}

func wantForm(t *testing.T, req tokenRequest, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if got := req.form.Get(k); got != v {
			t.Errorf("form %s = %q, want %q (form %v)", k, got, v, req.form)
		}
	}
}

func assertRefreshKept(t *testing.T, ts *tokenServer, cache *fakeCache, auth *fakeAuthorizer, res string) {
	t.Helper()
	if cache.erased != 0 || cache.tokens[res] == nil || cache.tokens[res].RefreshToken != "old-rt" {
		t.Errorf("cache erased %d times, holds %+v; want the refresh token kept", cache.erased, cache.tokens[res])
	}
	if auth.calls != 0 {
		t.Errorf("signed in %d times after a transient failure, want 0", auth.calls)
	}
	if got := onlyRequest(t, ts).form.Get("resource"); got != res {
		t.Errorf("refresh sent resource %q, want %q", got, res)
	}
}
