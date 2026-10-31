package cmd

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestGetRun(t *testing.T) {
	expiry := time.Unix(2000000000, 0)

	tests := []struct {
		name        string
		input       string
		wantAcquire string // Resource URL acquisition is called with; "" means not called
		wantOut     string
	}{
		{
			name:        "https request gets a Bearer credential",
			input:       "capability[]=authtype\nprotocol=https\nhost=git.example.com\n\n",
			wantAcquire: "https://git.example.com",
			wantOut:     "capability[]=authtype\nauthtype=Bearer\ncredential=at\npassword_expiry_utc=2000000000\noauth_refresh_token=rt\n",
		},
		{
			// #53: non-https requests were signed in for as https.
			name:  "http request is declined",
			input: "capability[]=authtype\nprotocol=http\nhost=git.example.com\n\n",
		},
		{
			// #44: authtype was only checked after a full sign-in.
			name:  "Git without authtype support is declined before sign-in",
			input: "protocol=https\nhost=git.example.com\n\n",
		},
		{
			name:  "missing host is declined",
			input: "capability[]=authtype\nprotocol=https\n\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			var acquired []string
			c := &getCommand{
				logger: slog.New(slog.DiscardHandler),
				stdin:  strings.NewReader(tt.input),
				stdout: &out,
				acquire: func(_ context.Context, resourceURL string) (*oauth2.Token, error) {
					acquired = append(acquired, resourceURL)
					return &oauth2.Token{AccessToken: "at", RefreshToken: "rt", Expiry: expiry}, nil
				},
			}

			if err := c.Run(context.Background(), nil, nil); err != nil {
				t.Fatalf("Run: unexpected error: %v", err)
			}

			switch {
			case tt.wantAcquire == "" && len(acquired) != 0:
				t.Errorf("acquisition called for %v, want no call", acquired)
			case tt.wantAcquire != "" && (len(acquired) != 1 || acquired[0] != tt.wantAcquire):
				t.Errorf("acquisition called for %v, want [%s]", acquired, tt.wantAcquire)
			}
			if out.String() != tt.wantOut {
				t.Errorf("stdout = %q, want %q", out.String(), tt.wantOut)
			}
		})
	}
}
