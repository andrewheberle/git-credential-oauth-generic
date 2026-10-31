package cmd

import (
	"context"
	"fmt"

	"github.com/andrewheberle/git-credential-oauth-generic/internal/pkg/version"
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
)

type versionCommand struct {
	root *rootCommand

	*simplecommand.Command
}

func (c *versionCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	_, err := fmt.Fprintf(c.root.env.stdout, "%s %s\n", cd.Root.Command.Name(), version.Version())
	return err
}
