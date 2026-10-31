package cmd

import (
	"context"

	"github.com/andrewheberle/git-credential-oauth-generic/internal/pkg/gitcredential"
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
)

type eraseCommand struct {
	root *rootCommand

	*simplecommand.Command
}

func (c *eraseCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	req, err := gitcredential.ReadRequest(c.root.env.stdin)
	if err != nil {
		return err
	}
	if resourceURL, ok := req.ResourceURL(); ok {
		c.root.cache("").Erase(ctx, resourceURL)
		c.root.logger.Debug("erased cached tokens", "url", resourceURL)
	}
	return nil
}
