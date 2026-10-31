package clientregistry

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andrewheberle/git-credential-oauth-generic/internal/pkg/acquire"
	"github.com/zalando/go-keyring"
)

const (
	testService  = "git-credential-oauth-generic-test"
	testResource = "https://git.example.com"
	testRedirect = "http://localhost:8400/callback"
)

var errNoKeyring = errors.New("no Secret Service on this machine")

// isolate points Git at an empty global config and swaps the OS keyring for an
// in-memory one, so tests never touch the user's real settings.
func isolate(t *testing.T) {
	t.Helper()
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(t.TempDir(), "gitconfig"))
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	keyring.MockInit()
}

// newRegistry returns a Registry logging to the returned buffer.
func newRegistry() (*Registry, *bytes.Buffer) {
	var logs bytes.Buffer
	return New(testService, slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))), &logs
}

func TestRegistry(t *testing.T) {
	tests := []struct {
		name     string
		remember map[string]acquire.Client // resource URL -> client
		setup    func(t *testing.T)        // runs after remember
		lookup   string
		want     acquire.Client
		wantLog  bool // a debug line about the unreadable secret
	}{
		{
			name:   "nothing registered",
			lookup: testResource,
			want:   acquire.Client{},
		},
		{
			name:     "confidential client round trip",
			remember: map[string]acquire.Client{testResource: {ID: "id-1", Secret: "secret-1", RedirectURI: testRedirect}},
			lookup:   testResource,
			want:     acquire.Client{ID: "id-1", Secret: "secret-1", RedirectURI: testRedirect},
		},
		{
			name:     "public client round trip",
			remember: map[string]acquire.Client{testResource: {ID: "id-1", RedirectURI: testRedirect}},
			lookup:   testResource,
			want:     acquire.Client{ID: "id-1", RedirectURI: testRedirect},
		},
		{
			name:     "clients are per resource URL",
			remember: map[string]acquire.Client{"https://other.example.com": {ID: "other", Secret: "s", RedirectURI: testRedirect}},
			lookup:   testResource,
			want:     acquire.Client{},
		},
		{
			name:     "URL match applies to paths on the host, secret included",
			remember: map[string]acquire.Client{testResource: {ID: "id-1", Secret: "secret-1", RedirectURI: testRedirect}},
			lookup:   testResource + "/org/repo.git",
			want:     acquire.Client{ID: "id-1", Secret: "secret-1", RedirectURI: testRedirect},
		},
		{
			name: "client ID set by hand has no redirect URI",
			setup: func(t *testing.T) {
				mustGit(t, "--global", "credential."+testResource+".oauthClientId", "by-hand")
			},
			lookup: testResource,
			want:   acquire.Client{ID: "by-hand"},
		},
		{
			name: "secret stored by an earlier version is still found",
			setup: func(t *testing.T) {
				mustGit(t, "--global", "credential."+testResource+".oauthClientId", "old-id")
				if err := keyring.Set(testService, testResource+":client_secret", "old-secret"); err != nil {
					t.Fatal(err)
				}
			},
			lookup: testResource,
			want:   acquire.Client{ID: "old-id", Secret: "old-secret"},
		},
		{
			name:     "unreadable keyring returns the client without its secret",
			remember: map[string]acquire.Client{testResource: {ID: "id-1", Secret: "secret-1", RedirectURI: testRedirect}},
			setup:    func(t *testing.T) { keyring.MockInitWithError(errNoKeyring) },
			lookup:   testResource,
			want:     acquire.Client{ID: "id-1", RedirectURI: testRedirect},
			wantLog:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isolate(t)
			t.Cleanup(keyring.MockInit)
			ctx := context.Background()
			r, logs := newRegistry()

			for res, client := range tt.remember {
				if err := r.Remember(ctx, res, client); err != nil {
					t.Fatalf("Remember: %v", err)
				}
			}
			if tt.setup != nil {
				tt.setup(t)
			}

			got, err := r.Lookup(ctx, tt.lookup)
			if err != nil {
				t.Fatalf("Lookup: %v", err)
			}
			if got != tt.want {
				t.Errorf("Lookup = %+v, want %+v", got, tt.want)
			}
			if strings.Contains(logs.String(), "level=WARN") {
				t.Errorf("Lookup warned; on keyring-less machines that would print on every run: %q", logs.String())
			}
			if logged := strings.Contains(logs.String(), "could not read client secret"); logged != tt.wantLog {
				t.Errorf("logged unreadable secret = %v, want %v (logs %q)", logged, tt.wantLog, logs.String())
			}
		})
	}
}

func TestRemember(t *testing.T) {
	t.Run("secret is keyed by client ID", func(t *testing.T) {
		isolate(t)
		r, _ := newRegistry()
		if err := r.Remember(context.Background(), testResource, acquire.Client{ID: "id-1", Secret: "secret-1", RedirectURI: testRedirect}); err != nil {
			t.Fatalf("Remember: %v", err)
		}
		if got, err := keyring.Get(testService, "client:id-1:client_secret"); err != nil || got != "secret-1" {
			t.Errorf("keyring client:id-1:client_secret = %q, %v; want secret-1", got, err)
		}
	})

	t.Run("confidential client is not saved when its secret can't be", func(t *testing.T) {
		isolate(t)
		t.Cleanup(keyring.MockInit)
		keyring.MockInitWithError(errNoKeyring)
		r, _ := newRegistry()
		ctx := context.Background()

		if err := r.Remember(ctx, testResource, acquire.Client{ID: "id-1", Secret: "secret-1", RedirectURI: testRedirect}); err == nil {
			t.Fatal("Remember: expected an error when the secret can't be saved")
		}
		got, err := r.Lookup(ctx, testResource)
		if err != nil {
			t.Fatalf("Lookup: %v", err)
		}
		if got != (acquire.Client{}) {
			t.Errorf("Lookup = %+v, want nothing saved", got)
		}
	})

	t.Run("public client never touches the keyring", func(t *testing.T) {
		isolate(t)
		t.Cleanup(keyring.MockInit)
		keyring.MockInitWithError(errNoKeyring)
		r, _ := newRegistry()
		ctx := context.Background()

		if err := r.Remember(ctx, testResource, acquire.Client{ID: "id-1", RedirectURI: testRedirect}); err != nil {
			t.Fatalf("Remember: %v", err)
		}
		got, err := r.Lookup(ctx, testResource)
		if err != nil {
			t.Fatalf("Lookup: %v", err)
		}
		if want := (acquire.Client{ID: "id-1", RedirectURI: testRedirect}); got != want {
			t.Errorf("Lookup = %+v, want %+v", got, want)
		}
	})

	t.Run("re-registered client replaces ID and redirect URI", func(t *testing.T) {
		isolate(t)
		r, _ := newRegistry()
		ctx := context.Background()

		if err := r.Remember(ctx, testResource, acquire.Client{ID: "old", Secret: "old-secret", RedirectURI: testRedirect}); err != nil {
			t.Fatalf("Remember: %v", err)
		}
		newRedirect := "http://localhost:9000/callback"
		if err := r.Remember(ctx, testResource, acquire.Client{ID: "new", RedirectURI: newRedirect}); err != nil {
			t.Fatalf("Remember: %v", err)
		}
		got, err := r.Lookup(ctx, testResource)
		if err != nil {
			t.Fatalf("Lookup: %v", err)
		}
		// The new public client must not pick up the old client's secret.
		if want := (acquire.Client{ID: "new", RedirectURI: newRedirect}); got != want {
			t.Errorf("Lookup = %+v, want %+v", got, want)
		}
	})
}

func TestLookupGitConfigError(t *testing.T) {
	isolate(t)
	// A global config that isn't valid Git config makes "git config" fail
	// with a status other than "not set".
	path := filepath.Join(t.TempDir(), "broken")
	if err := writeFile(path, "[credential\n"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", path)
	r, _ := newRegistry()

	if _, err := r.Lookup(context.Background(), testResource); err == nil {
		t.Error("Lookup: expected an error for unreadable Git config")
	}
}

func mustGit(t *testing.T, args ...string) {
	t.Helper()
	if err := gitConfigSet(context.Background(), args...); err != nil {
		t.Fatalf("git config %v: %v", args, err)
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
