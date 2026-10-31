package gitcredential

import (
	"strings"
	"testing"
)

func TestResourceMetadata(t *testing.T) {
	const cloudflare = `Bearer realm="OAuth", error="invalid_token", error_description="Missing or invalid access token", resource_metadata="https://git.example.com/.well-known/cloudflare-access-protected-resource/info/refs"`

	tests := []struct {
		name    string
		headers []string
		want    string
	}{
		{
			name:    "Cloudflare Access challenge (quoted values containing commas)",
			headers: []string{cloudflare},
			want:    "https://git.example.com/.well-known/cloudflare-access-protected-resource/info/refs",
		},
		{
			name:    "no headers",
			headers: nil,
			want:    "",
		},
		{
			name:    "Basic challenge only",
			headers: []string{`Basic realm="GitHub"`},
			want:    "",
		},
		{
			name:    "Bearer challenge without resource_metadata",
			headers: []string{`Bearer realm="example", error="invalid_token"`},
			want:    "",
		},
		{
			name:    "case-insensitive scheme and parameter name",
			headers: []string{`bEaReR Resource_Metadata="https://h/m"`},
			want:    "https://h/m",
		},
		{
			name:    "unquoted token value",
			headers: []string{`Bearer resource_metadata=abc`},
			want:    "abc",
		},
		{
			name:    "escaped quote inside a value",
			headers: []string{`Bearer realm="a \"quoted\" realm", resource_metadata="https://h/m"`},
			want:    "https://h/m",
		},
		{
			name:    "several challenges in one header",
			headers: []string{`Basic realm="x", Bearer realm="y", resource_metadata="https://h/m", Negotiate`},
			want:    "https://h/m",
		},
		{
			name:    "resource_metadata on a non-Bearer challenge is ignored",
			headers: []string{`Basic resource_metadata="https://h/wrong", Bearer resource_metadata="https://h/right"`},
			want:    "https://h/right",
		},
		{
			name:    "Basic token68 credentials don't confuse the parser",
			headers: []string{`Basic dXNlcjpwYXNz==, Bearer resource_metadata="https://h/m"`},
			want:    "https://h/m",
		},
		{
			name:    "first hint across several headers wins",
			headers: []string{`Basic realm="x"`, `Bearer resource_metadata="https://h/first"`, `Bearer resource_metadata="https://h/second"`},
			want:    "https://h/first",
		},
		{
			name:    "unterminated quoted string",
			headers: []string{`Bearer resource_metadata="https://h/m`},
			want:    "https://h/m",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := (Request{WWWAuthenticate: tt.headers}).ResourceMetadata(); got != tt.want {
				t.Errorf("ResourceMetadata() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReadRequestKeepsWWWAuthenticate(t *testing.T) {
	input := "protocol=https\nhost=git.example.com\n" +
		"wwwauth[]=Basic realm=\"x\"\n" +
		"wwwauth[]=Bearer resource_metadata=\"https://git.example.com/m\"\n\n"
	req, err := ReadRequest(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	if len(req.WWWAuthenticate) != 2 {
		t.Fatalf("WWWAuthenticate = %q, want 2 headers", req.WWWAuthenticate)
	}
	if got := req.ResourceMetadata(); got != "https://git.example.com/m" {
		t.Errorf("ResourceMetadata() = %q", got)
	}

	// An empty value resets the list, as for every key[] attribute.
	req, err = ReadRequest(strings.NewReader("wwwauth[]=Bearer resource_metadata=\"x\"\nwwwauth[]=\n"))
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	if len(req.WWWAuthenticate) != 0 {
		t.Errorf("WWWAuthenticate = %q after reset, want none", req.WWWAuthenticate)
	}
}
