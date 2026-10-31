package gitcredential

import (
	"bytes"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestReadRequest(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  Request
	}{
		{
			name:  "typical get from Git 2.45+",
			input: "capability[]=authtype\ncapability[]=state\nprotocol=https\nhost=git.example.com\n\n",
			want:  Request{Protocol: "https", Host: "git.example.com", Capabilities: []string{"authtype", "state"}},
		},
		{
			name:  "end of input without a blank line",
			input: "protocol=https\nhost=git.example.com",
			want:  Request{Protocol: "https", Host: "git.example.com"},
		},
		{
			name:  "stops at the blank line",
			input: "protocol=https\n\nhost=git.example.com\n",
			want:  Request{Protocol: "https"},
		},
		{
			name:  "empty value resets a list",
			input: "capability[]=authtype\ncapability[]=\ncapability[]=state\nprotocol=https\n",
			want:  Request{Protocol: "https", Capabilities: []string{"state"}},
		},
		{
			name:  "lines without = and unknown keys are ignored",
			input: "garbage\nprotocol=https\nusername=alice\npassword=hunter2\nhost=git.example.com:8443\n",
			want:  Request{Protocol: "https", Host: "git.example.com:8443"},
		},
		{
			name:  "values may contain =",
			input: "host=a=b\n",
			want:  Request{Host: "a=b"},
		},
		{
			name:  "empty input",
			input: "",
			want:  Request{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadRequest(strings.NewReader(tt.input))
			if err != nil {
				t.Fatalf("ReadRequest: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ReadRequest = %+v, want %+v", got, tt.want)
			}
		})
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("stdin closed") }

func TestReadRequestError(t *testing.T) {
	if _, err := ReadRequest(failingReader{}); err == nil {
		t.Error("ReadRequest: expected an error from a failing reader")
	}
}

func TestResourceURL(t *testing.T) {
	tests := []struct {
		name   string
		req    Request
		want   string
		wantOK bool
	}{
		{name: "https with host", req: Request{Protocol: "https", Host: "git.example.com"}, want: "https://git.example.com", wantOK: true},
		{name: "https with host and port", req: Request{Protocol: "https", Host: "git.example.com:8443"}, want: "https://git.example.com:8443", wantOK: true},
		{name: "http", req: Request{Protocol: "http", Host: "git.example.com"}},
		{name: "ssh", req: Request{Protocol: "ssh", Host: "git.example.com"}},
		{name: "missing host", req: Request{Protocol: "https"}},
		{name: "missing protocol", req: Request{Host: "git.example.com"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := tt.req.ResourceURL()
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("ResourceURL() = %q, %v; want %q, %v", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestSupports(t *testing.T) {
	req := Request{Capabilities: []string{"state", "authtype"}}
	if !req.Supports(CapabilityAuthtype) {
		t.Error("Supports(authtype) = false, want true")
	}
	if (Request{Capabilities: []string{"state"}}).Supports(CapabilityAuthtype) {
		t.Error("Supports(authtype) = true without the capability")
	}
}

func TestLogValueHasNoSecrets(t *testing.T) {
	req, err := ReadRequest(strings.NewReader("protocol=https\nhost=git.example.com\npassword=hunter2\ncredential=secret-token\noauth_refresh_token=secret-rt\n"))
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("request", "request", req)
	for _, secret := range []string{"hunter2", "secret-token", "secret-rt"} {
		if strings.Contains(buf.String(), secret) {
			t.Errorf("log output contains %q: %s", secret, buf.String())
		}
	}
	if !strings.Contains(buf.String(), "git.example.com") {
		t.Errorf("log output missing host: %s", buf.String())
	}
}

func TestWriteCredential(t *testing.T) {
	expiry := time.Unix(2000000000, 0)

	tests := []struct {
		name  string
		token *oauth2.Token
		want  string
	}{
		{
			name:  "access token only",
			token: &oauth2.Token{AccessToken: "at"},
			want:  "capability[]=authtype\nauthtype=Bearer\ncredential=at\n",
		},
		{
			name:  "with expiry and refresh token",
			token: &oauth2.Token{AccessToken: "at", RefreshToken: "rt", Expiry: expiry},
			want:  "capability[]=authtype\nauthtype=Bearer\ncredential=at\npassword_expiry_utc=2000000000\noauth_refresh_token=rt\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteCredential(&buf, tt.token); err != nil {
				t.Fatalf("WriteCredential: %v", err)
			}
			if buf.String() != tt.want {
				t.Errorf("WriteCredential wrote %q, want %q", buf.String(), tt.want)
			}
		})
	}

	t.Run("nil token", func(t *testing.T) {
		if err := WriteCredential(&bytes.Buffer{}, nil); err == nil {
			t.Error("WriteCredential(nil): expected an error")
		}
	})
}

func TestWriteCapabilities(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCapabilities(&buf); err != nil {
		t.Fatalf("WriteCapabilities: %v", err)
	}
	if want := "version 0\ncapability authtype\n"; buf.String() != want {
		t.Errorf("WriteCapabilities wrote %q, want %q", buf.String(), want)
	}
}
