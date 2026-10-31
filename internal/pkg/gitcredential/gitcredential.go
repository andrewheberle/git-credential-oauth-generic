// Package gitcredential implements this helper's side of the Git credential
// helper protocol (https://git-scm.com/docs/git-credential): reading the
// Credential request Git writes to the helper's stdin, and writing the
// response Git reads from its stdout.
package gitcredential

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"

	"golang.org/x/oauth2"
)

// CapabilityAuthtype is the capability Git (2.45+) announces when it can
// accept a credential with an authtype, which Bearer tokens need.
const CapabilityAuthtype = "authtype"

// maxLineLength bounds a single request line; Git sends a few short lines,
// but WWW-Authenticate values (wwwauth[]) can be long.
const maxLineLength = 1 << 20

// Request is a Credential request: the attributes Git sends a helper. Only
// the attributes this helper uses are kept; other secrets Git may pass along
// (such as a password from another helper) are never stored.
type Request struct {
	Protocol     string
	Host         string
	Capabilities []string

	// OAuthRefreshToken is the refresh token Git passes along from an earlier
	// helper, typically git-credential-cache returning an expired credential.
	// It is confidential and never logged.
	OAuthRefreshToken string
}

// ReadRequest reads a Credential request. Following the protocol, it stops at
// a blank line or end of input, ignores lines without "=", accumulates
// repeated "key[]" attributes, and resets such a list on an empty value.
func ReadRequest(r io.Reader) (Request, error) {
	var req Request

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), maxLineLength)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "protocol":
			req.Protocol = value
		case "host":
			req.Host = value
		case "oauth_refresh_token":
			req.OAuthRefreshToken = value
		case "capability[]":
			if value == "" {
				req.Capabilities = nil
			} else {
				req.Capabilities = append(req.Capabilities, value)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return Request{}, fmt.Errorf("reading credential request: %w", err)
	}

	return req, nil
}

// ResourceURL returns the Resource URL the request is for, and false if the
// request is not one this helper handles: anything but https with a host.
// Such requests should be declined silently so Git tries the next helper.
func (r Request) ResourceURL() (string, bool) {
	if r.Protocol != "https" || r.Host == "" {
		return "", false
	}
	return "https://" + r.Host, true
}

// Supports reports whether Git announced the named capability.
func (r Request) Supports(capability string) bool {
	for _, c := range r.Capabilities {
		if c == capability {
			return true
		}
	}
	return false
}

// LogValue logs the request without any secret attributes, reporting only
// whether a refresh token was passed.
func (r Request) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("protocol", r.Protocol),
		slog.String("host", r.Host),
		slog.Any("capabilities", r.Capabilities),
		slog.Bool("has_refresh_token", r.OAuthRefreshToken != ""),
	)
}

// WriteCredential writes token as a Bearer credential response. The
// capability line comes first, as the protocol requires of directives that
// later values depend on; the rest follow in a fixed order. Git must have
// announced CapabilityAuthtype for the response to be understood.
func WriteCredential(w io.Writer, token *oauth2.Token) error {
	if token == nil {
		return errors.New("writing credential: token is nil")
	}

	var b strings.Builder
	b.WriteString("capability[]=" + CapabilityAuthtype + "\n")
	b.WriteString("authtype=Bearer\n")
	b.WriteString("credential=" + token.AccessToken + "\n")
	if !token.Expiry.IsZero() {
		b.WriteString("password_expiry_utc=" + strconv.FormatInt(token.Expiry.UTC().Unix(), 10) + "\n")
	}
	if token.RefreshToken != "" {
		b.WriteString("oauth_refresh_token=" + token.RefreshToken + "\n")
	}

	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("writing credential: %w", err)
	}
	return nil
}

// WriteCapabilities writes the response to "git credential capability":
// the protocol version and the capabilities this helper supports.
func WriteCapabilities(w io.Writer) error {
	// https://git-scm.com/docs/git-credential#CAPA-IOFMT
	if _, err := io.WriteString(w, "version 0\ncapability "+CapabilityAuthtype+"\n"); err != nil {
		return fmt.Errorf("writing capabilities: %w", err)
	}
	return nil
}
