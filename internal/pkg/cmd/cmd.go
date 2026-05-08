package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
	"github.com/zalando/go-keyring"
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

// parse reads the Git credential helper key=value input from stdin.
func parse(input string) map[string]string {
	lines := strings.Split(input, "\n")
	pairs := make(map[string]string, len(lines))
	for _, line := range lines {
		if key, value, ok := strings.Cut(line, "="); ok {
			_, exists := pairs[key]
			if exists && strings.HasSuffix(key, "[]") {
				pairs[key] += "\n" + value
			} else {
				pairs[key] = value
			}
		}
	}
	return pairs
}

// getClientSecret retrieves the client secret from the OS keyring for the
// given resource URL. Returns empty string if not found.
func getClientSecret(resourceURL string) string {
	return getKeychainItem(resourceURL, "client_secret", false)
}

// setClientSecret stores the client secret in the OS keyring for the given
// resource URL.
func setClientSecret(resourceURL, secret string) error {
	return setKeychainItem(resourceURL, "client_secret", secret, false)
}

// getKeychainItem retrieves a value from the OS keyring for the given resource URL
// and item name.
func getKeychainItem(resourceURL, item string, nopersist bool) string {
	// no-op when nopersist set
	if nopersist {
		return ""
	}

	value, err := keyring.Get(keyringService, resourceURL+":"+item)
	if err != nil {
		return ""
	}
	return value
}

// setKeychainItem stores a value in the OS keyring for the given resource URL
// and item name.
func setKeychainItem(resourceURL, item, value string, nopersist bool) error {
	// no-op when nopersist set
	if nopersist {
		return nil
	}

	return keyring.Set(keyringService, resourceURL+":"+item, value)
}

// deleteKeychainItem removes a value from the OS keyring for the given resource
// URL and item name.
func deleteKeychainItem(resourceURL, item string, nopersist bool) {
	// no-op when nopersist set
	if nopersist {
		return
	}

	_ = keyring.Delete(keyringService, resourceURL+":"+item)
}
