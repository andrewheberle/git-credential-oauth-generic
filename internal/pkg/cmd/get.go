package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/andrewheberle/git-credential-oauth-generic/internal/pkg/acquire"
	"github.com/andrewheberle/git-credential-oauth-generic/internal/pkg/authorize"
	"github.com/andrewheberle/git-credential-oauth-generic/internal/pkg/clientregistry"
	"github.com/andrewheberle/git-credential-oauth-generic/internal/pkg/version"
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
)

type getCommand struct {
	nopersist    bool
	callbackport int

	logger *slog.Logger

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

	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("reading stdin: %w", err)
	}
	pairs := parse(string(input))
	slog.Debug("input", "pairs", pairs)

	protocol := pairs["protocol"]
	host := pairs["host"]
	if protocol == "" || host == "" {
		return fmt.Errorf("missing protocol or host in input")

	}
	if protocol != "https" {
		// Only HTTPS makes sense for OAuth.
		c.logger.Debug("skipping non-https protocol", "protocol", protocol)
	}

	resourceURL := fmt.Sprintf("https://%s", host)

	acquirer := acquire.New(acquire.Config{
		Cache:   newTokenCache(c.nopersist),
		Clients: clientregistry.New(keyringService),
		Authorize: (&authorize.Loopback{
			Out:    os.Stderr,
			Logger: c.logger,
		}).Authorize,
		CallbackPort: c.callbackport,
		Logger:       c.logger,
	})

	token, err := acquirer.Acquire(ctx, resourceURL)
	switch {
	case errors.Is(err, acquire.ErrNotOAuthHost):
		c.logger.Debug("not an OAuth host", "url", resourceURL, "error", err)

		// Host does not support RFC 9728; silently exit so Git falls through
		// to the next credential helper.
		return nil
	case errors.Is(err, acquire.ErrClientIDRequired):
		fmt.Fprintf(os.Stderr, "host %s requires a client ID but provides no registration endpoint\n", host)
		fmt.Fprintf(os.Stderr, "set one manually: git config --global credential.%s.oauthClientId <ID>\n", resourceURL)
		return nil
	case err != nil:
		return err
	}

	// --- Output credentials for Git ---
	// "A capability[] directive must precede any value depending on it and these
	// directives should be the first item announced in the protocol."
	// https://git-scm.com/docs/git-credential
	fmt.Println("capability[]=authtype")

	// Bearer token output requires Git 2.45+ authtype capability support.
	// Basic auth encoding would destroy Bearer token semantics so we refuse
	// to fall back — the caller must upgrade Git.
	if !strings.Contains(pairs["capability[]"], "authtype") {
		fmt.Fprintln(os.Stderr, "error: Git does not support authtype capability (requires Git 2.45+)")
		return nil
	}

	output := map[string]string{
		"authtype":   "Bearer",
		"credential": token.AccessToken,
	}
	if !token.Expiry.IsZero() {
		output["password_expiry_utc"] = fmt.Sprintf("%d", token.Expiry.UTC().Unix())
	}
	if token.RefreshToken != "" {
		output["oauth_refresh_token"] = token.RefreshToken
	}
	c.logger.Debug("generated output", "output", output)
	for k, v := range output {
		fmt.Printf("%s=%s\n", k, v)
	}

	return nil
}
