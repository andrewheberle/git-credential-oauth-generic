package clientregistry

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/andrewheberle/git-credential-oauth-generic/internal/pkg/acquire"
	"github.com/zalando/go-keyring"
)

const testService = "git-credential-oauth-generic-test"

// isolate points Git at an empty global config and swaps the OS keyring for an
// in-memory one, so tests never touch the user's real settings.
func isolate(t *testing.T) {
	t.Helper()
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(t.TempDir(), "gitconfig"))
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	keyring.MockInit()
}

func TestRegistry(t *testing.T) {
	const resource = "https://git.example.com"

	tests := []struct {
		name     string
		remember map[string]acquire.Client // resource URL -> client, applied in map order
		lookup   string
		want     acquire.Client
	}{
		{
			name:   "nothing registered",
			lookup: resource,
			want:   acquire.Client{},
		},
		{
			name:     "confidential client round trip",
			remember: map[string]acquire.Client{resource: {ID: "id-1", Secret: "secret-1"}},
			lookup:   resource,
			want:     acquire.Client{ID: "id-1", Secret: "secret-1"},
		},
		{
			name:     "public client round trip",
			remember: map[string]acquire.Client{resource: {ID: "id-1"}},
			lookup:   resource,
			want:     acquire.Client{ID: "id-1"},
		},
		{
			name:     "clients are per resource URL",
			remember: map[string]acquire.Client{"https://other.example.com": {ID: "other", Secret: "s"}},
			lookup:   resource,
			want:     acquire.Client{},
		},
		{
			name:     "URL match applies to paths on the host",
			remember: map[string]acquire.Client{resource: {ID: "id-1"}},
			lookup:   resource + "/org/repo.git",
			want:     acquire.Client{ID: "id-1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isolate(t)
			ctx := context.Background()
			r := New(testService)

			for res, client := range tt.remember {
				if err := r.Remember(ctx, res, client); err != nil {
					t.Fatalf("Remember: %v", err)
				}
			}

			got, err := r.Lookup(ctx, tt.lookup)
			if err != nil {
				t.Fatalf("Lookup: %v", err)
			}
			if got != tt.want {
				t.Errorf("Lookup = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestRememberReplacesSecret(t *testing.T) {
	isolate(t)
	ctx := context.Background()
	r := New(testService)
	const resource = "https://git.example.com"

	if err := r.Remember(ctx, resource, acquire.Client{ID: "old", Secret: "old-secret"}); err != nil {
		t.Fatalf("Remember: %v", err)
	}
	// A re-registered public client must not inherit the old secret.
	if err := r.Remember(ctx, resource, acquire.Client{ID: "new"}); err != nil {
		t.Fatalf("Remember: %v", err)
	}

	got, err := r.Lookup(ctx, resource)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if want := (acquire.Client{ID: "new"}); got != want {
		t.Errorf("Lookup = %+v, want %+v", got, want)
	}
}
