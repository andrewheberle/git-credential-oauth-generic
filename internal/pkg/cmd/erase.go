package cmd

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
)

type eraseCommand struct {
	logger    *slog.Logger
	nopersist bool

	*simplecommand.Command
}

func (c *eraseCommand) Init(cd *simplecobra.Commandeer) error {
	if err := c.Command.Init(cd); err != nil {
		return err
	}

	cmd := cd.CobraCommand
	cmd.PersistentFlags().BoolVar(&c.nopersist, "nopersist", false, "rely on another helper to persist credentials")

	return nil
}

func (c *eraseCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	if err := c.Command.PreRun(this, runner); err != nil {
		return err
	}

	return nil
}

func (c *eraseCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	// no-op if we do no persist data
	if c.nopersist {
		return nil
	}

	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("error reading stdin: %w", err)
	}
	pairs := parse(string(input))
	host := pairs["host"]
	protocol := pairs["protocol"]
	if protocol == "https" && host != "" {
		resourceURL := fmt.Sprintf("https://%s", host)
		deleteKeychainItem(resourceURL, "access_token", c.nopersist)
		deleteKeychainItem(resourceURL, "refresh_token", c.nopersist)
		deleteKeychainItem(resourceURL, "password_expiry_utc", c.nopersist)
		c.logger.Debug("erased tokens from keyring", "url", resourceURL)
	}
	return nil
}
