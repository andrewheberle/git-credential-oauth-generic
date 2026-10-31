package acquire

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
)

// cloudflareHintPath is where Cloudflare Access's resource_metadata hint
// points for a Git request to /info/refs.
const cloudflareHintPath = "/.well-known/cloudflare-access-protected-resource/info/refs"

func TestDiscoveryHint(t *testing.T) {
	// The hinted document Cloudflare Access serves: same authorization server
	// as the root document, but a resource scoped to the requested path.
	const cloudflareHinted = `{"resource":"{{URL}}/info/refs","protected":true,"authorization_servers":["{{URL}}"]}`
	root := ok(cloudflareResourceMeta)
	as := ok(cloudflareASMeta)

	tests := []struct {
		name   string
		routes map[string]route
		hint   string // "{{URL}}" is the test server's URL

		wantErr     error    // nil means the sign-in completes
		wantFetched []string // paths that must have been requested
		wantSkipped []string // paths that must not have been requested
	}{
		{
			name:        "hint is followed when the root document doesn't exist",
			routes:      map[string]route{cloudflareHintPath: ok(cloudflareHinted), asPath: as},
			hint:        "{{URL}}" + cloudflareHintPath,
			wantFetched: []string{cloudflareHintPath},
			wantSkipped: []string{prPath},
		},
		{
			name:        "hint is tried before the root document",
			routes:      map[string]route{cloudflareHintPath: ok(cloudflareHinted), prPath: root, asPath: as},
			hint:        "{{URL}}" + cloudflareHintPath,
			wantFetched: []string{cloudflareHintPath},
			wantSkipped: []string{prPath},
		},
		{
			// httptest's client routes example.com hosts to the test server,
			// so a followed hint would show up as a request for its path.
			name:        "hint to another host is ignored",
			routes:      map[string]route{cloudflareHintPath: ok(cloudflareHinted), prPath: root, asPath: as},
			hint:        "https://attacker.example.com" + cloudflareHintPath,
			wantFetched: []string{prPath},
			wantSkipped: []string{cloudflareHintPath},
		},
		{
			name:        "hint over plain http is ignored",
			routes:      map[string]route{cloudflareHintPath: ok(cloudflareHinted), prPath: root, asPath: as},
			hint:        "http-of:{{URL}}" + cloudflareHintPath,
			wantFetched: []string{prPath},
			wantSkipped: []string{cloudflareHintPath},
		},
		{
			name:        "hint without metadata falls back to the root document",
			routes:      map[string]route{prPath: root, asPath: as},
			hint:        "{{URL}}" + cloudflareHintPath,
			wantFetched: []string{cloudflareHintPath, prPath},
		},
		{
			name:        "hint server error is reported, not skipped",
			routes:      map[string]route{cloudflareHintPath: {status: http.StatusBadGateway}, prPath: root, asPath: as},
			hint:        "{{URL}}" + cloudflareHintPath,
			wantErr:     ErrDiscovery,
			wantSkipped: []string{prPath},
		},
		{
			name:    "hinted metadata for a resource elsewhere is rejected",
			routes:  map[string]route{cloudflareHintPath: ok(`{"resource":"https://elsewhere.example.com/info/refs","authorization_servers":["{{URL}}"]}`), asPath: as},
			hint:    "{{URL}}" + cloudflareHintPath,
			wantErr: ErrDiscovery,
		},
		{
			name:    "hinted resource that only shares a prefix with the host is rejected",
			routes:  map[string]route{cloudflareHintPath: ok(`{"resource":"{{URL}}0/info/refs","authorization_servers":["{{URL}}"]}`), asPath: as},
			hint:    "{{URL}}" + cloudflareHintPath,
			wantErr: ErrDiscovery,
		},
		{
			name:        "no hint uses the root document as before",
			routes:      map[string]route{prPath: root, asPath: as},
			wantFetched: []string{prPath},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				srv     *httptest.Server
				mu      sync.Mutex
				fetched []string
			)
			srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				fetched = append(fetched, r.URL.Path)
				mu.Unlock()
				rt, found := tt.routes[r.URL.Path]
				if !found {
					http.NotFound(w, r)
					return
				}
				w.WriteHeader(rt.status)
				_, _ = w.Write([]byte(strings.ReplaceAll(rt.body, "{{URL}}", srv.URL)))
			}))
			t.Cleanup(srv.Close)

			hint := strings.ReplaceAll(tt.hint, "{{URL}}", srv.URL)
			hint = strings.Replace(hint, "http-of:https://", "http://", 1)

			reg := newFakeRegistry()
			reg.clients[srv.URL] = Client{ID: "known-id"}
			auth := &fakeAuthorizer{token: validToken("login-at")}
			a := New(Config{
				Cache:        newFakeCache(),
				Clients:      reg,
				Authorize:    auth.authorize,
				HTTPClient:   srv.Client(),
				CallbackPort: callbackPort,
			})

			token, err := a.Acquire(context.Background(), srv.URL, hint)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Acquire error = %v, want %v", err, tt.wantErr)
				}
			} else {
				if err != nil {
					t.Fatalf("Acquire: unexpected error: %v", err)
				}
				if token == nil || token.AccessToken != "login-at" {
					t.Fatalf("Acquire token = %+v, want the signed-in token", token)
				}
				// Tokens stay host-wide, whatever path the hint was for.
				if auth.req.Resource != srv.URL {
					t.Errorf("sign-in resource = %q, want %q", auth.req.Resource, srv.URL)
				}
			}

			mu.Lock()
			defer mu.Unlock()
			for _, p := range tt.wantFetched {
				if !slices.Contains(fetched, p) {
					t.Errorf("%s was not requested (requests: %v)", p, fetched)
				}
			}
			for _, p := range tt.wantSkipped {
				if slices.Contains(fetched, p) {
					t.Errorf("%s was requested but shouldn't have been (requests: %v)", p, fetched)
				}
			}
		})
	}
}

func TestSameOrigin(t *testing.T) {
	resource, err := url.Parse("https://git.example.com")
	if err != nil {
		t.Fatal(err)
	}
	withPort, err := url.Parse("https://git.example.com:8443")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		resource *url.URL
		hint     string
		want     bool
	}{
		{resource, "https://git.example.com/.well-known/x", true},
		{resource, "https://GIT.example.com/x", true},
		{resource, "https://git.example.com:443/x", true},
		{resource, "http://git.example.com/x", false},
		{resource, "https://git.example.com:8443/x", false},
		{resource, "https://evil.example.com/x", false},
		{resource, "https://git.example.com.evil.com/x", false},
		{resource, "//git.example.com/x", false},
		{resource, "::not a url", false},
		{withPort, "https://git.example.com:8443/x", true},
		{withPort, "https://git.example.com/x", false},
	}
	for _, tt := range tests {
		if got := sameOrigin(tt.resource, tt.hint); got != tt.want {
			t.Errorf("sameOrigin(%s, %q) = %v, want %v", tt.resource, tt.hint, got, tt.want)
		}
	}
}
