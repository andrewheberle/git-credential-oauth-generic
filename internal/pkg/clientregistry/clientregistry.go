// Package clientregistry stores the Registered client for a resource URL: the
// client ID and the redirect URI it was registered with in Git config (where
// users can also set a client ID by hand), and the client secret, if any, in
// the OS keyring, keyed by client ID.
package clientregistry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"

	"github.com/andrewheberle/git-credential-oauth-generic/internal/pkg/acquire"
	"github.com/zalando/go-keyring"
)

// Git config variables, looked up with --get-urlmatch so that
// credential.<url>.<name> applies per host.
const (
	clientIDKey    = "credential.oauthClientId"
	redirectURIKey = "credential.oauthRedirectUri"
)

// Registry stores Registered clients in Git config and the OS keyring.
type Registry struct {
	service string
	logger  *slog.Logger
}

// New returns a Registry that keeps client secrets in the OS keyring under
// the given service name. logger receives diagnostics; nil discards them.
func New(service string, logger *slog.Logger) *Registry {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Registry{service: service, logger: logger}
}

// Lookup returns the Registered client for resourceURL, or a zero Client if no
// client ID is configured. It returns an error only if Git config cannot be
// read. A secret that cannot be read from the keyring is logged at debug
// level and the client is returned without it: public clients need none (and
// on a machine without a keyring this happens on every run, so it is not a
// warning), and a confidential client then fails visibly at the token
// endpoint rather than being silently replaced.
func (r *Registry) Lookup(ctx context.Context, resourceURL string) (acquire.Client, error) {
	id, err := gitConfigGet(ctx, "--get-urlmatch", clientIDKey, resourceURL)
	if err != nil {
		return acquire.Client{}, err
	}
	if id == "" {
		return acquire.Client{}, nil
	}

	redirectURI, err := gitConfigGet(ctx, "--get-urlmatch", redirectURIKey, resourceURL)
	if err != nil {
		return acquire.Client{}, err
	}

	secret, err := r.secret(id, resourceURL)
	if err != nil {
		r.logger.Debug("could not read client secret from keyring; continuing without it", "error", err)
		secret = ""
	}

	return acquire.Client{ID: id, Secret: secret, RedirectURI: redirectURI}, nil
}

// secret reads the client secret for id, falling back (read-only) to the key
// used by earlier versions, which was the resource URL.
func (r *Registry) secret(id, resourceURL string) (string, error) {
	secret, err := keyring.Get(r.service, secretKey(id))
	if err == nil {
		return secret, nil
	}
	if !errors.Is(err, keyring.ErrNotFound) {
		return "", err
	}

	secret, err = keyring.Get(r.service, legacySecretKey(resourceURL))
	if errors.Is(err, keyring.ErrNotFound) {
		return "", nil
	}
	return secret, err
}

// Remember stores client for resourceURL. The secret, if any, is saved first:
// if it cannot be saved, nothing is written and an error is returned, because
// a client ID without its secret would fail on every later run. Then the ID
// and redirect URI are written to the user's global Git config.
func (r *Registry) Remember(ctx context.Context, resourceURL string, client acquire.Client) error {
	if client.Secret != "" {
		if err := keyring.Set(r.service, secretKey(client.ID), client.Secret); err != nil {
			return fmt.Errorf("writing client secret to keyring (client not saved): %w", err)
		}
	}

	var errs []error
	if err := gitConfigSet(ctx, "--global", "credential."+resourceURL+".oauthClientId", client.ID); err != nil {
		errs = append(errs, err)
	}
	if client.RedirectURI != "" {
		if err := gitConfigSet(ctx, "--global", "credential."+resourceURL+".oauthRedirectUri", client.RedirectURI); err != nil {
			errs = append(errs, err)
		}
	} else if err := gitConfigUnset(ctx, "--global", "--unset", "credential."+resourceURL+".oauthRedirectUri"); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

func secretKey(clientID string) string {
	return "client:" + clientID + ":client_secret"
}

func legacySecretKey(resourceURL string) string {
	return resourceURL + ":client_secret"
}

// gitConfigGet runs "git config <args>" and returns its trimmed output. Exit
// status 1 means the variable is not set, which is reported as "" with no
// error.
func gitConfigGet(ctx context.Context, args ...string) (string, error) {
	out, err := gitConfig(ctx, args...)
	if exitCode(err) == 1 {
		return "", nil
	}
	return out, err
}

// gitConfigSet runs "git config <args>" to write a variable.
func gitConfigSet(ctx context.Context, args ...string) error {
	_, err := gitConfig(ctx, args...)
	return err
}

// gitConfigUnset runs "git config <args>" to remove a variable. Exit status 5
// means it was not set, which is not an error.
func gitConfigUnset(ctx context.Context, args ...string) error {
	_, err := gitConfig(ctx, args...)
	if exitCode(err) == 5 {
		return nil
	}
	return err
}

// gitConfig runs "git config <args>" and returns its trimmed output.
func gitConfig(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"config"}, args...)...)
	var stderr strings.Builder
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git config %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

func exitCode(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}
