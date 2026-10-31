package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"

	"github.com/andrewheberle/git-credential-oauth-generic/internal/pkg/acquire"
	"github.com/andrewheberle/git-credential-oauth-generic/internal/pkg/clientregistry"
	"github.com/andrewheberle/git-credential-oauth-generic/internal/pkg/tokencache"
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
	"golang.org/x/oauth2"
)

const (
	keyringService = "git-credential-oauth-generic"
)

// tokenCache stores the tokens obtained for a resource URL between runs.
type tokenCache interface {
	Load(ctx context.Context, resourceURL string) (*oauth2.Token, error)
	Save(ctx context.Context, resourceURL string, token *oauth2.Token) error
	Erase(ctx context.Context, resourceURL string)
}

// env is everything a run of the helper talks to outside its own code: Git
// through stdin and stdout, the user through stderr, and the stores, network
// and browser that Credential acquisition uses.
type env struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer

	// tokenCache is the persistent Token cache; --nopersist replaces it with
	// one that stores nothing.
	tokenCache tokenCache
	clients    acquire.ClientRegistry

	// httpClient is used for discovery, registration and refresh; nil means
	// Credential acquisition's default.
	httpClient *http.Client

	// authorize is the Authorizer; nil means the browser-based Loopback,
	// built with the run's logger and stderr.
	authorize acquire.Authorize
}

// Execute runs the helper with the given command line against the real
// stdin, stdout, stderr, OS keyring, Git config, network and browser.
func Execute(ctx context.Context, args []string) error {
	return execute(ctx, args, env{
		stdin:      os.Stdin,
		stdout:     os.Stdout,
		stderr:     os.Stderr,
		tokenCache: tokencache.NewKeyring(keyringService),
		clients:    clientregistry.New(keyringService),
	})
}

// execute runs the helper with the given command line against e.
func execute(ctx context.Context, args []string, e env) error {
	level := new(slog.LevelVar)
	root := &rootCommand{
		Command:  simplecommand.New("git-credential-oauth-generic", "A Git credential helper for generic RFC 8707 OAuth "),
		env:      e,
		logger:   slog.New(slog.NewTextHandler(e.stderr, &slog.HandlerOptions{Level: level})),
		logLevel: level,
	}
	root.SubCommands = []simplecobra.Commander{
		&eraseCommand{
			Command: simplecommand.New("erase", "Erase credentials [called by Git]"),
			root:    root,
		},
		&getCommand{
			Command: simplecommand.New("get", "Generate credential [called by Git]"),
			root:    root,
		},
		&capabilityCommand{
			Command: simplecommand.New("capability", "Display capabilities [called by Git]"),
			root:    root,
		},
		&versionCommand{
			Command: simplecommand.New("version", "Print version"),
			root:    root,
		},
		simplecommand.New("store", "No-op [called by Git]"),
	}

	x, err := simplecobra.New(root)
	if err != nil {
		return err
	}

	if _, err := x.Execute(ctx, args); err != nil {
		return err
	}

	return nil
}

// rootCommand holds the flags and state shared by every subcommand. Flags are
// declared here, as persistent flags, because Git runs a configured helper
// such as "oauth-generic --nopersist" as "git-credential-oauth-generic
// --nopersist get", with the flags before the subcommand.
type rootCommand struct {
	verbose      bool
	nopersist    bool
	callbackport int

	env      env
	logger   *slog.Logger
	logLevel *slog.LevelVar

	*simplecommand.Command
}

func (c *rootCommand) Init(cd *simplecobra.Commandeer) error {
	if err := c.Command.Init(cd); err != nil {
		return err
	}

	cmd := cd.CobraCommand
	cmd.SetIn(c.env.stdin)
	cmd.SetOut(c.env.stdout)
	cmd.SetErr(c.env.stderr)
	cmd.PersistentFlags().BoolVar(&c.verbose, "verbose", false, "log debug information to stderr")
	cmd.PersistentFlags().BoolVar(&c.nopersist, "nopersist", false, "rely on another helper to persist credentials")
	cmd.PersistentFlags().IntVar(&c.callbackport, "port", 8400, "callback port for oauth flow")

	return nil
}

func (c *rootCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	if c.verbose {
		c.logLevel.Set(slog.LevelDebug)
	}

	return nil
}

func (c *rootCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	// Usage goes to stderr here, as this is an error; --help goes to stdout.
	if _, err := fmt.Fprint(c.env.stderr, cd.CobraCommand.UsageString()); err != nil {
		c.logger.Error("could not display usage", "error", err)
	}

	return errors.New("please run a sub-command")
}

// cache returns the Token cache for this run: the persistent one, or one that
// stores nothing when a chained Git credential helper handles persistence
// (--nopersist).
func (c *rootCommand) cache() tokenCache {
	if c.nopersist {
		return tokencache.NewNoop()
	}
	return c.env.tokenCache
}
