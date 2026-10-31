package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/andrewheberle/git-credential-oauth-generic/internal/pkg/acquire"
	"github.com/andrewheberle/git-credential-oauth-generic/internal/pkg/authorize"
	"github.com/andrewheberle/git-credential-oauth-generic/internal/pkg/clientregistry"
	"github.com/andrewheberle/git-credential-oauth-generic/internal/pkg/gitcredential"
	"github.com/andrewheberle/git-credential-oauth-generic/internal/pkg/version"
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
	"golang.org/x/oauth2"
)

type getCommand struct {
	nopersist    bool
	callbackport int

	logger *slog.Logger

	// Test hooks; nil means the real stdin, stdout and Credential acquisition.
	stdin   io.Reader
	stdout  io.Writer
	acquire func(ctx context.Context, resourceURL string) (*oauth2.Token, error)

	*simplecommand.Command
}

func (c *getCommand) Init(cd *simplecobra.Commandeer) error {
	if err := c.Command.Init(cd); err != nil {
		return err
	}

	cmd := cd.CobraCommand
	cmd.PersistentFlags().BoolVar(&c.nopersist, "nopersist", false, "rely on another helper to persist credentials")
	cmd.PersistentFlags().IntVar(&c.callbackport, "port", 8400, "callback port for oauth flow")

	return nil
}

func (c *getCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	if err := c.Command.PreRun(this, runner); err != nil {
		return err
	}

	return nil
}

func (c *getCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	c.logger.Debug("starting helper", "version", version.Version())

	stdin, stdout := c.stdin, c.stdout
	if stdin == nil {
		stdin = os.Stdin
	}
	if stdout == nil {
		stdout = os.Stdout
	}

	req, err := gitcredential.ReadRequest(stdin)
	if err != nil {
		return err
	}
	c.logger.Debug("credential request", "request", req)

	resourceURL, ok := req.ResourceURL()
	if !ok {
		// Not an https request with a host; decline silently so Git falls
		// through to the next credential helper.
		c.logger.Debug("declining request: not https with a host", "request", req)
		return nil
	}

	// Bearer token output requires Git 2.45+ authtype capability support.
	// Basic auth encoding would destroy Bearer token semantics so we refuse
	// to fall back, and check before any network or browser work.
	if !req.Supports(gitcredential.CapabilityAuthtype) {
		fmt.Fprintln(os.Stderr, "error: Git does not support authtype capability (requires Git 2.45+)")
		return nil
	}

	acquireToken := c.acquire
	if acquireToken == nil {
		acquireToken = c.newAcquirer().Acquire
	}

	token, err := acquireToken(ctx, resourceURL)
	switch {
	case errors.Is(err, acquire.ErrNotOAuthHost):
		c.logger.Debug("not an OAuth host", "url", resourceURL, "error", err)

		// Host does not support RFC 9728; silently exit so Git falls through
		// to the next credential helper.
		return nil
	case errors.Is(err, acquire.ErrClientIDRequired):
		fmt.Fprintf(os.Stderr, "host %s requires a client ID but provides no registration endpoint\n", req.Host)
		fmt.Fprintf(os.Stderr, "set one manually: git config --global credential.%s.oauthClientId <ID>\n", resourceURL)
		return nil
	case err != nil:
		return err
	}

	if err := gitcredential.WriteCredential(stdout, token); err != nil {
		return err
	}
	c.logger.Debug("wrote credential",
		"has_expiry", !token.Expiry.IsZero(),
		"has_refresh_token", token.RefreshToken != "",
	)

	return nil
}

// newAcquirer builds Credential acquisition from the real Token cache, client
// registry and browser Authorizer.
func (c *getCommand) newAcquirer() *acquire.Acquirer {
	return acquire.New(acquire.Config{
		Cache:   newTokenCache(c.nopersist),
		Clients: clientregistry.New(keyringService),
		Authorize: (&authorize.Loopback{
			Out:    os.Stderr,
			Logger: c.logger,
		}).Authorize,
		CallbackPort: c.callbackport,
		Logger:       c.logger,
	})
}
