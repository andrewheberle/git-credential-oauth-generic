// Package clientregistry stores the Registered client for a resource URL: the
// client ID in Git config, where users can also set it by hand, and the
// client secret, if any, in the OS keyring.
package clientregistry

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/andrewheberle/git-credential-oauth-generic/internal/pkg/acquire"
	"github.com/zalando/go-keyring"
)

// clientIDKey is the Git config variable holding the client ID, looked up
// with --get-urlmatch so credential.<url>.oauthClientId applies per host.
const clientIDKey = "credential.oauthClientId"

// Registry stores Registered clients in Git config and the OS keyring.
type Registry struct {
	service string
}

// New returns a Registry that keeps client secrets in the OS keyring under
// the given service name.
func New(service string) *Registry {
	return &Registry{service: service}
}

// Lookup returns the Registered client for resourceURL, or a zero Client if no
// client ID is configured.
func (r *Registry) Lookup(ctx context.Context, resourceURL string) (acquire.Client, error) {
	id, err := gitConfigGet(ctx, "--get-urlmatch", clientIDKey, resourceURL)
	if err != nil {
		return acquire.Client{}, err
	}
	if id == "" {
		return acquire.Client{}, nil
	}

	secret, err := keyring.Get(r.service, secretKey(resourceURL))
	if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return acquire.Client{}, fmt.Errorf("reading client secret from keyring: %w", err)
	}

	return acquire.Client{ID: id, Secret: secret}, nil
}

// Remember stores client for resourceURL: the ID in the user's global Git
// config, the secret in the keyring. An empty secret removes any old one.
func (r *Registry) Remember(ctx context.Context, resourceURL string, client acquire.Client) error {
	var errs []error
	if err := gitConfigSet(ctx, "--global", "credential."+resourceURL+".oauthClientId", client.ID); err != nil {
		errs = append(errs, err)
	}

	if client.Secret != "" {
		if err := keyring.Set(r.service, secretKey(resourceURL), client.Secret); err != nil {
			errs = append(errs, fmt.Errorf("writing client secret to keyring: %w", err))
		}
	} else {
		if err := keyring.Delete(r.service, secretKey(resourceURL)); err != nil && !errors.Is(err, keyring.ErrNotFound) {
			errs = append(errs, fmt.Errorf("removing client secret from keyring: %w", err))
		}
	}

	return errors.Join(errs...)
}

func secretKey(resourceURL string) string {
	return resourceURL + ":client_secret"
}

// gitConfigGet runs "git config <args>" and returns its trimmed output. Exit
// status 1 means the variable is not set, which is reported as "" with no
// error.
func gitConfigGet(ctx context.Context, args ...string) (string, error) {
	out, err := gitConfig(ctx, args...)
	if exitErr := (*exec.ExitError)(nil); errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return "", nil
	}
	return out, err
}

// gitConfigSet runs "git config <args>" to write a variable.
func gitConfigSet(ctx context.Context, args ...string) error {
	_, err := gitConfig(ctx, args...)
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
