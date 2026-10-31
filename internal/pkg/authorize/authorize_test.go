package authorize

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

const (
	testResource = "https://git.example.com"
	testCode     = "the-code"
)

// fakeIdP is an httptest authorization server. /authorize redirects straight
// back to the redirect URI (no login page); /token checks PKCE and the
// resource parameter before issuing a token.
type fakeIdP struct {
	*httptest.Server
	t *testing.T

	denyWith, denyDesc string // if set, /authorize redirects back with this error
	failExchange       bool   // /token rejects the code

	exchangeStarted chan struct{} // if set, signalled when /token is hit
	exchangeGate    chan struct{} // if set, /token waits for it to close

	mu        sync.Mutex
	challenge string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	idp := &fakeIdP{t: t}
	idp.Server = httptest.NewServer(http.HandlerFunc(idp.serve))
	t.Cleanup(idp.Close)
	return idp
}

func (idp *fakeIdP) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/authorize":
		q := r.URL.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("resource") != testResource {
			http.Error(w, "missing PKCE or resource", http.StatusBadRequest)
			return
		}
		idp.mu.Lock()
		idp.challenge = q.Get("code_challenge")
		idp.mu.Unlock()

		back := url.Values{"state": {q.Get("state")}}
		if idp.denyWith != "" {
			back.Set("error", idp.denyWith)
			back.Set("error_description", idp.denyDesc)
		} else {
			back.Set("code", testCode)
		}
		http.Redirect(w, r, q.Get("redirect_uri")+"?"+back.Encode(), http.StatusFound)

	case "/token":
		if idp.exchangeStarted != nil {
			idp.exchangeStarted <- struct{}{}
		}
		if idp.exchangeGate != nil {
			<-idp.exchangeGate
		}
		_ = r.ParseForm()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		idp.mu.Lock()
		pkceOK := base64.RawURLEncoding.EncodeToString(sum[:]) == idp.challenge
		idp.mu.Unlock()
		if idp.failExchange || !pkceOK || r.Form.Get("code") != testCode || r.Form.Get("resource") != testResource {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "idp-at", "token_type": "Bearer", "expires_in": 3600,
		})

	default:
		http.NotFound(w, r)
	}
}

// page is one response the test browser received.
type page struct {
	status int
	body   string
}

// browser plays the user's browser with a plain HTTP client.
type browser struct {
	t      *testing.T
	client *http.Client
}

func (b *browser) visit(rawURL string) page {
	resp, err := b.client.Get(rawURL)
	if err != nil {
		b.t.Errorf("browser: GET %s: %v", rawURL, err)
		return page{}
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return page{status: resp.StatusCode, body: string(body)}
}

var continueLink = regexp.MustCompile(`class="continue" href="([^"]+)"`)

// authURL returns the authorization URL the landing page links to.
func (b *browser) authURL(landing page) string {
	m := continueLink.FindStringSubmatch(landing.body)
	if m == nil {
		b.t.Errorf("landing page has no Continue link: %q", landing.body)
		return ""
	}
	return html.UnescapeString(m[1])
}

// signIn opens the landing page and follows its Continue link through the
// authorization server back to the callback.
func (b *browser) signIn(landingURL string) (landing, result page) {
	landing = b.visit(landingURL)
	if u := b.authURL(landing); u != "" {
		result = b.visit(u)
	}
	return landing, result
}

// stateOf returns the state parameter of an authorization URL.
func stateOf(t *testing.T, authURL string) string {
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parsing %q: %v", authURL, err)
	}
	return u.Query().Get("state")
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("finding a free port: %v", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func TestAuthorize(t *testing.T) {
	type env struct {
		idp      *fakeIdP
		b        *browser
		landing  string // landing page URL
		callback string // redirect URI
	}

	tests := []struct {
		name    string
		setup   func(idp *fakeIdP)
		timeout time.Duration
		openErr error
		// browse runs in its own goroutine once the browser is "opened".
		browse func(t *testing.T, e env)

		wantToken string
		wantErr   string
		wantOut   []string // substrings of the instructions written to Out
	}{
		{
			name: "successful sign-in",
			browse: func(t *testing.T, e env) {
				landing, result := e.b.signIn(e.landing)
				// #43: the landing page used to be written to stderr.
				if landing.status != http.StatusOK || !strings.Contains(landing.body, "Continue") {
					t.Errorf("landing page = %d %q, want 200 with a Continue link", landing.status, landing.body)
				}
				if !strings.Contains(landing.body, html.EscapeString(e.idp.URL+"/authorize?")) {
					t.Errorf("landing page does not show the authorization URL: %q", landing.body)
				}
				if result.status != http.StatusOK || !strings.Contains(result.body, "Success") {
					t.Errorf("result page = %d %q, want 200 Success", result.status, result.body)
				}
			},
			wantToken: "idp-at",
			wantOut:   []string{"Please complete authentication", "/authorize?"},
		},
		{
			name: "authorization error is shown escaped and fails the sign-in",
			setup: func(idp *fakeIdP) {
				idp.denyWith = "access_denied"
				idp.denyDesc = `<script>alert(1)</script>`
			},
			browse: func(t *testing.T, e env) {
				_, result := e.b.signIn(e.landing)
				if result.status != http.StatusBadRequest {
					t.Errorf("result status = %d, want 400", result.status)
				}
				if strings.Contains(result.body, "<script>alert(1)") {
					t.Errorf("error_description rendered unescaped: %q", result.body)
				}
				if !strings.Contains(result.body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
					t.Errorf("error_description missing from page: %q", result.body)
				}
			},
			wantErr: "access_denied",
		},
		{
			name: "callback with the wrong state is ignored",
			browse: func(t *testing.T, e env) {
				stray := e.b.visit(e.callback + "?state=wrong&code=" + testCode)
				if stray.status != http.StatusBadRequest || !strings.Contains(stray.body, "ignored") {
					t.Errorf("stray callback page = %d %q, want 400 saying it was ignored", stray.status, stray.body)
				}
				if strings.Contains(stray.body, "Success") {
					t.Errorf("stray callback shown success: %q", stray.body)
				}
				_, result := e.b.signIn(e.landing)
				if result.status != http.StatusOK {
					t.Errorf("real sign-in after a stray callback = %d %q", result.status, result.body)
				}
			},
			wantToken: "idp-at",
		},
		{
			name:  "failed code exchange is shown and fails the sign-in",
			setup: func(idp *fakeIdP) { idp.failExchange = true },
			browse: func(t *testing.T, e env) {
				_, result := e.b.signIn(e.landing)
				if result.status != http.StatusBadGateway || strings.Contains(result.body, "Success") {
					t.Errorf("result page = %d %q, want 502 without success", result.status, result.body)
				}
			},
			wantErr: "token exchange",
		},
		{
			name: "callback without a code fails the sign-in",
			browse: func(t *testing.T, e env) {
				landing := e.b.visit(e.landing)
				state := stateOf(t, e.b.authURL(landing))
				result := e.b.visit(e.callback + "?state=" + url.QueryEscape(state))
				if result.status != http.StatusBadRequest {
					t.Errorf("result status = %d, want 400", result.status)
				}
			},
			wantErr: "missing code",
		},
		{
			name: "second callback is answered, not blocked",
			setup: func(idp *fakeIdP) {
				idp.exchangeStarted = make(chan struct{}, 1)
				idp.exchangeGate = make(chan struct{})
			},
			browse: func(t *testing.T, e env) {
				landing := e.b.visit(e.landing)
				authURL := e.b.authURL(landing)
				first := make(chan page, 1)
				go func() { first <- e.b.visit(authURL) }()

				// While the first callback is mid-exchange, send another.
				<-e.idp.exchangeStarted
				second := e.b.visit(e.callback + "?state=" + url.QueryEscape(stateOf(t, authURL)) + "&code=" + testCode)
				if second.status != http.StatusConflict || !strings.Contains(second.body, "already completed") {
					t.Errorf("second callback page = %d %q, want 409 already completed", second.status, second.body)
				}
				close(e.idp.exchangeGate)
				if res := <-first; res.status != http.StatusOK {
					t.Errorf("first callback page = %d %q, want 200", res.status, res.body)
				}
			},
			wantToken: "idp-at",
		},
		{
			name:    "times out when no callback arrives",
			timeout: 200 * time.Millisecond,
			wantErr: "timed out",
		},
		{
			name:    "browser that fails to open still gets the URL printed",
			timeout: 200 * time.Millisecond,
			openErr: errors.New("no display"),
			wantErr: "timed out",
			wantOut: []string{"Could not open a browser", "no display", "/authorize?"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := newFakeIdP(t)
			if tt.setup != nil {
				tt.setup(idp)
			}
			port := freePort(t)
			e := env{
				idp:      idp,
				b:        &browser{t: t, client: &http.Client{Timeout: 5 * time.Second}},
				landing:  fmt.Sprintf("http://localhost:%d/auth", port),
				callback: fmt.Sprintf("http://localhost:%d/callback", port),
			}

			browsed := make(chan struct{})
			var out bytes.Buffer
			l := &Loopback{
				Out:     &out,
				Timeout: tt.timeout,
				Open: func(landing string) error {
					if landing != e.landing {
						t.Errorf("opened %q, want %q", landing, e.landing)
					}
					if tt.openErr != nil || tt.browse == nil {
						close(browsed)
						return tt.openErr
					}
					go func() {
						defer close(browsed)
						tt.browse(t, e)
					}()
					return nil
				},
			}
			if l.Timeout == 0 {
				l.Timeout = 10 * time.Second
			}

			cfg := oauth2.Config{
				ClientID:    "client-id",
				RedirectURL: e.callback,
				Endpoint: oauth2.Endpoint{
					AuthURL:   idp.URL + "/authorize",
					TokenURL:  idp.URL + "/token",
					AuthStyle: oauth2.AuthStyleInParams,
				},
			}
			ctx := context.WithValue(context.Background(), oauth2.HTTPClient, idp.Client())

			token, err := l.Authorize(ctx, cfg, testResource)

			select {
			case <-browsed:
			case <-time.After(10 * time.Second):
				t.Fatal("browser did not finish")
			}

			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Authorize error = %v, want one containing %q", err, tt.wantErr)
				}
			} else if err != nil {
				t.Errorf("Authorize: unexpected error: %v", err)
			} else if token == nil || token.AccessToken != tt.wantToken {
				t.Errorf("Authorize token = %+v, want access token %q", token, tt.wantToken)
			}

			for _, want := range tt.wantOut {
				if !strings.Contains(out.String(), want) {
					t.Errorf("instructions %q do not contain %q", out.String(), want)
				}
			}
		})
	}
}

func TestPagesRender(t *testing.T) {
	for name, tmpl := range pages {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tmpl.ExecuteTemplate(&buf, "page", pageData{Title: "t", Version: "v"}); err != nil {
				t.Fatalf("rendering %s: %v", name, err)
			}
			if !strings.Contains(buf.String(), "<!DOCTYPE html>") {
				t.Errorf("%s rendered without the page layout: %q", name, buf.String())
			}
		})
	}
}
