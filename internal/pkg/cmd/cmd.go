package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/andrewheberle/git-credential-oauth-generic/internal/pkg/tokencache"
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
	"golang.org/x/oauth2"
)

const (
	keyringService = "git-credential-oauth-generic"
)

type rootCommand struct {
	verbose      bool
	nopersist    bool
	callbackport int

	logger *slog.Logger

	*simplecommand.Command
}

var logLevel = new(slog.LevelVar)

func (c *rootCommand) Init(cd *simplecobra.Commandeer) error {
	if err := c.Command.Init(cd); err != nil {
		return err
	}

	cmd := cd.CobraCommand
	cmd.PersistentFlags().BoolVar(&c.verbose, "verbose", false, "log debug information to stderr")
	cmd.PersistentFlags().BoolVar(&c.nopersist, "nopersist", false, "rely on another helper to persist credentials")
	cmd.PersistentFlags().IntVar(&c.callbackport, "port", 8400, "callback port for oauth flow")

	return nil
}

func (c *rootCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	if err := c.Command.PreRun(this, runner); err != nil {
		return err
	}

	if c.verbose {
		logLevel.Set(slog.LevelDebug)
	}

	return nil
}

func (c *rootCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	cmd := cd.CobraCommand
	if err := cmd.Usage(); err != nil {
		c.logger.Error("could not display usage", "error", err)
	}

	return fmt.Errorf("please run a sub-command")
}

func Execute(ctx context.Context, args []string) error {
	// set up logger
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

	rootCmd := &rootCommand{
		Command: simplecommand.New("git-credential-oauth-generic", "A Git credential helper for generic RFC 8707 OAuth "),
		logger:  logger,
	}
	rootCmd.SubCommands = []simplecobra.Commander{
		&eraseCommand{
			Command: simplecommand.New("erase", "Erase credentials [called by Git]"),
			logger:  logger,
		},
		&getCommand{
			Command: simplecommand.New("get", "Generate credential [called by Git]"),
			logger:  logger,
		},
		&capabilityCommand{
			Command: simplecommand.New("capability", "Display capabilities [called by Git]"),
			logger:  logger,
		},
		&versionCommand{
			Command: simplecommand.New("version", "Print version"),
			logger:  logger,
		},
		simplecommand.New("store", "No-op [called by Git]"),
	}

	// Set up simplecobra
	x, err := simplecobra.New(rootCmd)
	if err != nil {
		return err
	}

	// run command with the provided args
	if _, err := x.Execute(ctx, args); err != nil {
		return err
	}

	return nil
}

// tokenCache stores the tokens obtained for a resource URL between runs.
type tokenCache interface {
	Load(ctx context.Context, resourceURL string) (*oauth2.Token, error)
	Save(ctx context.Context, resourceURL string, token *oauth2.Token) error
	Erase(ctx context.Context, resourceURL string)
}

// newTokenCache returns the Token cache to use: the OS keyring, or nothing at
// all when a chained Git credential helper handles persistence (--nopersist).
func newTokenCache(nopersist bool) tokenCache {
	if nopersist {
		return tokencache.NewNoop()
	}
	return tokencache.NewKeyring(keyringService)
}
