package cmd

import (
	"context"
	"log/slog"
	"os"

	"github.com/andrewheberle/git-credential-oauth-generic/internal/pkg/gitcredential"
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
	req, err := gitcredential.ReadRequest(os.Stdin)
	if err != nil {
		return err
	}
	if resourceURL, ok := req.ResourceURL(); ok {
		newTokenCache(c.nopersist).Erase(ctx, resourceURL)
		c.logger.Debug("erased cached tokens", "url", resourceURL)
	}
	return nil
}
