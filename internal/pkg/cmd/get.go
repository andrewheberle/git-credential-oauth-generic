package cmd

import (
	"context"
	"errors"
	"fmt"

	"github.com/andrewheberle/git-credential-oauth-generic/internal/pkg/acquire"
	"github.com/andrewheberle/git-credential-oauth-generic/internal/pkg/authorize"
	"github.com/andrewheberle/git-credential-oauth-generic/internal/pkg/gitcredential"
	"github.com/andrewheberle/git-credential-oauth-generic/internal/pkg/version"
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
)

type getCommand struct {
	root *rootCommand

	*simplecommand.Command
}

func (c *getCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	e, logger := c.root.env, c.root.logger
	logger.Debug("starting helper", "version", version.Version())

	req, err := gitcredential.ReadRequest(e.stdin)
	if err != nil {
		return err
	}
	logger.Debug("credential request", "request", req)

	resourceURL, ok := req.ResourceURL()
	if !ok {
		// Not an https request with a host; decline silently so Git falls
		// through to the next credential helper.
		logger.Debug("declining request: not https with a host", "request", req)
		return nil
	}

	// Bearer token output requires Git 2.45+ authtype capability support.
	// Basic auth encoding would destroy Bearer token semantics so we refuse
	// to fall back, and check before any network or browser work.
	if !req.Supports(gitcredential.CapabilityAuthtype) {
		_, _ = fmt.Fprintln(e.stderr, "error: Git does not support authtype capability (requires Git 2.45+)")
		return nil
	}

	token, err := c.newAcquirer().Acquire(ctx, resourceURL)
	switch {
	case errors.Is(err, acquire.ErrNotOAuthHost):
		logger.Debug("not an OAuth host", "url", resourceURL, "error", err)

		// Host does not support RFC 9728; silently exit so Git falls through
		// to the next credential helper.
		return nil
	case errors.Is(err, acquire.ErrClientIDRequired):
		_, _ = fmt.Fprintf(e.stderr, "host %s requires a client ID but provides no registration endpoint\n", req.Host)
		_, _ = fmt.Fprintf(e.stderr, "set one manually: git config --global credential.%s.oauthClientId <ID>\n", resourceURL)
		return nil
	case err != nil:
		return err
	}

	if err := gitcredential.WriteCredential(e.stdout, token); err != nil {
		return err
	}
	logger.Debug("wrote credential",
		"has_expiry", !token.Expiry.IsZero(),
		"has_refresh_token", token.RefreshToken != "",
	)

	return nil
}

// newAcquirer assembles Credential acquisition for this run from the
// environment and flags.
func (c *getCommand) newAcquirer() *acquire.Acquirer {
	e, logger := c.root.env, c.root.logger

	authz := e.authorize
	if authz == nil {
		authz = (&authorize.Loopback{Out: e.stderr, Logger: logger}).Authorize
	}

	return acquire.New(acquire.Config{
		Cache:        c.root.cache(),
		Clients:      e.clients,
		Authorize:    authz,
		HTTPClient:   e.httpClient,
		CallbackPort: c.root.callbackport,
		Logger:       logger,
	})
}
