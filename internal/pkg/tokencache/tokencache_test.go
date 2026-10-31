package tokencache

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
	"golang.org/x/oauth2"
)

const (
	testService  = "git-credential-oauth-generic-test"
	testResource = "https://git.example.com"
)

// Whole seconds, because expiry is stored as Unix seconds.
var testExpiry = time.Unix(2000000000, 0)

func TestKeyring(t *testing.T) {
	tests := []struct {
		name string
		// setup runs against a fresh in-memory keyring.
		setup func(t *testing.T, c *Keyring)
		want  *oauth2.Token
	}{
		{
			name:  "nothing stored",
			setup: func(t *testing.T, c *Keyring) {},
			want:  nil,
		},
		{
			name: "round trip",
			setup: func(t *testing.T, c *Keyring) {
				mustSave(t, c, &oauth2.Token{AccessToken: "at", RefreshToken: "rt", Expiry: testExpiry})
			},
			want: &oauth2.Token{AccessToken: "at", RefreshToken: "rt", Expiry: testExpiry},
		},
		{
			name: "refresh token only",
			setup: func(t *testing.T, c *Keyring) {
				mustSave(t, c, &oauth2.Token{RefreshToken: "rt"})
			},
			want: &oauth2.Token{RefreshToken: "rt"},
		},
		{
			name: "access token without expiry is dropped, refresh token kept",
			setup: func(t *testing.T, c *Keyring) {
				mustSave(t, c, &oauth2.Token{AccessToken: "at", RefreshToken: "rt"})
			},
			want: &oauth2.Token{RefreshToken: "rt"},
		},
		{
			name: "access token without expiry or refresh token is nothing",
			setup: func(t *testing.T, c *Keyring) {
				mustSave(t, c, &oauth2.Token{AccessToken: "at"})
			},
			want: nil,
		},
		{
			name: "unparsable expiry drops access token",
			setup: func(t *testing.T, c *Keyring) {
				mustSet(t, testResource+":access_token", "at")
				mustSet(t, testResource+":refresh_token", "rt")
				mustSet(t, testResource+":password_expiry_utc", "soon")
			},
			want: &oauth2.Token{RefreshToken: "rt"},
		},
		{
			name: "save replaces the whole entry",
			setup: func(t *testing.T, c *Keyring) {
				mustSave(t, c, &oauth2.Token{AccessToken: "old-at", RefreshToken: "old-rt", Expiry: testExpiry})
				// No expiry: the old expiry must not pair with the new access token.
				mustSave(t, c, &oauth2.Token{AccessToken: "new-at", RefreshToken: "new-rt"})
			},
			want: &oauth2.Token{RefreshToken: "new-rt"},
		},
		{
			name: "save removes a refresh token the new token lacks",
			setup: func(t *testing.T, c *Keyring) {
				mustSave(t, c, &oauth2.Token{AccessToken: "old-at", RefreshToken: "old-rt", Expiry: testExpiry})
				mustSave(t, c, &oauth2.Token{AccessToken: "new-at", Expiry: testExpiry})
			},
			want: &oauth2.Token{AccessToken: "new-at", Expiry: testExpiry},
		},
		{
			name: "erase",
			setup: func(t *testing.T, c *Keyring) {
				mustSave(t, c, &oauth2.Token{AccessToken: "at", RefreshToken: "rt", Expiry: testExpiry})
				c.Erase(context.Background(), testResource)
			},
			want: nil,
		},
		{
			name: "entries are per resource URL",
			setup: func(t *testing.T, c *Keyring) {
				if err := c.Save(context.Background(), "https://other.example.com", &oauth2.Token{AccessToken: "at", RefreshToken: "rt", Expiry: testExpiry}); err != nil {
					t.Fatalf("Save: %v", err)
				}
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyring.MockInit()
			c := NewKeyring(testService)
			tt.setup(t, c)

			got, err := c.Load(context.Background(), testResource)
			if err != nil {
				t.Fatalf("Load: unexpected error: %v", err)
			}
			assertToken(t, got, tt.want)
		})
	}
}

func TestKeyringErrors(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	keyringDown := errors.New("keyring unavailable")

	tests := []struct {
		name    string
		ctx     context.Context
		backend error
		wantErr error
	}{
		{name: "cancelled context", ctx: cancelled, wantErr: context.Canceled},
		{name: "keyring unavailable", ctx: context.Background(), backend: keyringDown, wantErr: keyringDown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.backend != nil {
				keyring.MockInitWithError(tt.backend)
			} else {
				keyring.MockInit()
			}
			c := NewKeyring(testService)

			if _, err := c.Load(tt.ctx, testResource); !errors.Is(err, tt.wantErr) {
				t.Errorf("Load: got error %v, want %v", err, tt.wantErr)
			}
			if err := c.Save(tt.ctx, testResource, &oauth2.Token{AccessToken: "at", Expiry: testExpiry}); !errors.Is(err, tt.wantErr) {
				t.Errorf("Save: got error %v, want %v", err, tt.wantErr)
			}
		})
	}

	t.Run("nil token", func(t *testing.T) {
		keyring.MockInit()
		if err := NewKeyring(testService).Save(context.Background(), testResource, nil); err == nil {
			t.Error("Save(nil): expected an error")
		}
	})
}

func TestNoop(t *testing.T) {
	keyring.MockInit()
	ctx := context.Background()
	c := NewNoop()

	if err := c.Save(ctx, testResource, &oauth2.Token{AccessToken: "at", RefreshToken: "rt", Expiry: testExpiry}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := c.Load(ctx, testResource)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	assertToken(t, got, nil)
	c.Erase(ctx, testResource)

	// Nothing may reach the OS keyring.
	if _, err := keyring.Get(testService, testResource+":access_token"); !errors.Is(err, keyring.ErrNotFound) {
		t.Errorf("Noop wrote to the keyring: %v", err)
	}
}

func mustSave(t *testing.T, c *Keyring, token *oauth2.Token) {
	t.Helper()
	if err := c.Save(context.Background(), testResource, token); err != nil {
		t.Fatalf("Save: %v", err)
	}
}

func mustSet(t *testing.T, user, value string) {
	t.Helper()
	if err := keyring.Set(testService, user, value); err != nil {
		t.Fatalf("keyring.Set: %v", err)
	}
}

func assertToken(t *testing.T, got, want *oauth2.Token) {
	t.Helper()
	if want == nil {
		if got != nil {
			t.Fatalf("got %+v, want nil", got)
		}
		return
	}
	if got == nil {
		t.Fatalf("got nil, want %+v", want)
	}
	if got.AccessToken != want.AccessToken || got.RefreshToken != want.RefreshToken || !got.Expiry.Equal(want.Expiry) {
		t.Errorf("got {access=%q refresh=%q expiry=%v}, want {access=%q refresh=%q expiry=%v}",
			got.AccessToken, got.RefreshToken, got.Expiry, want.AccessToken, want.RefreshToken, want.Expiry)
	}
}
