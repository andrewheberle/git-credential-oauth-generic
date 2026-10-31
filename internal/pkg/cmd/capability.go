package cmd

import (
	"context"

	"github.com/andrewheberle/git-credential-oauth-generic/internal/pkg/gitcredential"
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
)

type capabilityCommand struct {
	root *rootCommand

	*simplecommand.Command
}

func (c *capabilityCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	return gitcredential.WriteCapabilities(c.root.env.stdout)
}
