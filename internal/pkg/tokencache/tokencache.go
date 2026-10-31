// Package tokencache stores the OAuth tokens the helper has obtained for a
// resource URL, so later Git operations can reuse or refresh them instead of
// sending the user through the browser again.
//
// The Token cache holds the access token, refresh token and expiry only. The
// client secret belongs to client registration and is stored elsewhere.
package tokencache

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/zalando/go-keyring"
	"golang.org/x/oauth2"
)

// Keyring item names, appended to the resource URL to form the keyring user.
// Changing these orphans tokens cached by earlier versions.
const (
	accessTokenItem  = "access_token"
	refreshTokenItem = "refresh_token"
	expiryItem       = "password_expiry_utc"
)

// Keyring is a Token cache backed by the OS keyring (Secret Service on Linux,
// Keychain on macOS, Credential Manager on Windows).
type Keyring struct {
	service string
}

// NewKeyring returns a Token cache that stores entries in the OS keyring under
// the given service name.
func NewKeyring(service string) *Keyring {
	return &Keyring{service: service}
}

// Load returns the token stored for resourceURL exactly as stored: it may be
// expired, or hold only a refresh token, so callers check Valid() and fall
// back to RefreshToken. It returns (nil, nil) when nothing usable is stored,
// and an error only when the keyring itself cannot be read.
//
// An access token without a stored expiry is dropped (its refresh token is
// kept), because oauth2 would otherwise treat it as never expiring.
func (k *Keyring) Load(ctx context.Context, resourceURL string) (*oauth2.Token, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	access, err := k.get(resourceURL, accessTokenItem)
	if err != nil {
		return nil, err
	}
	refresh, err := k.get(resourceURL, refreshTokenItem)
	if err != nil {
		return nil, err
	}
	expiry, err := k.get(resourceURL, expiryItem)
	if err != nil {
		return nil, err
	}

	token := &oauth2.Token{RefreshToken: refresh}
	if access != "" && expiry != "" {
		if secs, err := strconv.ParseInt(expiry, 10, 64); err == nil {
			token.AccessToken = access
			token.Expiry = time.Unix(secs, 0)
		}
	}

	if token.AccessToken == "" && token.RefreshToken == "" {
		return nil, nil
	}

	return token, nil
}

// Save replaces the entry for resourceURL with token: fields that are set are
// written, fields that are empty are removed, so nothing from a previous token
// survives alongside the new one.
func (k *Keyring) Save(ctx context.Context, resourceURL string, token *oauth2.Token) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if token == nil {
		return errors.New("saving token: token is nil")
	}

	var expiry string
	if !token.Expiry.IsZero() {
		expiry = strconv.FormatInt(token.Expiry.UTC().Unix(), 10)
	}

	return errors.Join(
		k.put(resourceURL, accessTokenItem, token.AccessToken),
		k.put(resourceURL, refreshTokenItem, token.RefreshToken),
		k.put(resourceURL, expiryItem, expiry),
	)
}

// Erase removes everything stored for resourceURL. It is best-effort: a
// failure to delete leaves at worst a token that the next Load reports and
// the server rejects.
func (k *Keyring) Erase(ctx context.Context, resourceURL string) {
	for _, item := range []string{accessTokenItem, refreshTokenItem, expiryItem} {
		_ = keyring.Delete(k.service, key(resourceURL, item))
	}
}

// get reads one item, treating "not found" as empty.
func (k *Keyring) get(resourceURL, item string) (string, error) {
	value, err := keyring.Get(k.service, key(resourceURL, item))
	if errors.Is(err, keyring.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("reading %s from keyring: %w", item, err)
	}
	return value, nil
}

// put writes one item, or deletes it when value is empty.
func (k *Keyring) put(resourceURL, item, value string) error {
	if value == "" {
		err := keyring.Delete(k.service, key(resourceURL, item))
		if err != nil && !errors.Is(err, keyring.ErrNotFound) {
			return fmt.Errorf("removing %s from keyring: %w", item, err)
		}
		return nil
	}
	if err := keyring.Set(k.service, key(resourceURL, item), value); err != nil {
		return fmt.Errorf("writing %s to keyring: %w", item, err)
	}
	return nil
}

func key(resourceURL, item string) string {
	return resourceURL + ":" + item
}

// RefreshOnly is the Token cache used with --nopersist, where a chained Git
// credential helper (git-credential-cache) persists the credential instead.
// It holds only the refresh token Git passed back in the Credential request,
// so an expired credential can be refreshed without a browser sign-in, and
// stores nothing.
type RefreshOnly struct {
	refreshToken string
}

// NewRefreshOnly returns a Token cache holding refreshToken, which may be
// empty.
func NewRefreshOnly(refreshToken string) RefreshOnly {
	return RefreshOnly{refreshToken: refreshToken}
}

// Load returns a token with only the refresh token set, or nil if there is
// none. It is the same for every resource URL: a request carries the refresh
// token for its own resource only.
func (c RefreshOnly) Load(context.Context, string) (*oauth2.Token, error) {
	if c.refreshToken == "" {
		return nil, nil
	}
	return &oauth2.Token{RefreshToken: c.refreshToken}, nil
}

// Save discards the token; the chained helper stores what Git is given.
func (RefreshOnly) Save(context.Context, string, *oauth2.Token) error { return nil }

// Erase does nothing; the chained helper erases its own entry.
func (RefreshOnly) Erase(context.Context, string) {}
