package cmd

import (
	"context"
	"log/slog"
	"os"

	"github.com/andrewheberle/git-credential-oauth-generic/internal/pkg/gitcredential"
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
)

type capabilityCommand struct {
	logger *slog.Logger

	*simplecommand.Command
}

func (c *capabilityCommand) Init(cd *simplecobra.Commandeer) error {
	if err := c.Command.Init(cd); err != nil {
		return err
	}

	return nil
}

func (c *capabilityCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	if err := c.Command.PreRun(this, runner); err != nil {
		return err
	}

	return nil
}

func (c *capabilityCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	return gitcredential.WriteCapabilities(os.Stdout)
}
