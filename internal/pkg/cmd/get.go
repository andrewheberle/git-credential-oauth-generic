package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/andrewheberle/git-credential-oauth-generic/internal/pkg/acquire"
	"github.com/andrewheberle/git-credential-oauth-generic/internal/pkg/clientregistry"
	"github.com/andrewheberle/git-credential-oauth-generic/internal/pkg/templates"
	"github.com/andrewheberle/git-credential-oauth-generic/internal/pkg/version"
	"github.com/andrewheberle/opener"
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
	"golang.org/x/oauth2"
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
		Authorize: func(ctx context.Context, cfg oauth2.Config, resourceURL string) (*oauth2.Token, error) {
			return c.getToken(ctx, cfg, resourceURL, c.callbackport)
		},
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

// getToken performs the PKCE authorization code flow, opening the browser and
// listening for the callback on the given port. The resource parameter (RFC
// 8707) is appended to the authorization URL.
func (c *getCommand) getToken(ctx context.Context, o2c oauth2.Config, resourceURL string, callbackPort int) (*oauth2.Token, error) {
	// Create a derived context with a 5-minute timeout to allow for
	// browser profile switching, URL copy-pasting, or MFA challenges.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	state := oauth2.GenerateVerifier()
	verifier := oauth2.GenerateVerifier()

	// Listen on the callback port before opening the browser.
	addr := fmt.Sprintf("localhost:%d", callbackPort)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", addr, err)
	}

	// Build the authorization URL with PKCE and RFC 8707 resource parameter.
	authURL := o2c.AuthCodeURL(
		state,
		oauth2.S256ChallengeOption(verifier),
		oauth2.SetAuthURLParam("resource", resourceURL),
	)

	queries := make(chan url.Values, 1)
	// ready chan ensures the server loop has started before we trigger the browser.
	ready := make(chan struct{})

	mux := http.NewServeMux()

	// /auth serves the landing page. It displays the IdP authorization URL as
	// both a copyable link and a Continue button, so the user can open it in
	// the correct browser profile if needed.
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if err := templates.ExecuteTemplate(
			os.Stderr,
			"start",
			struct {
				Title, AuthUrl, Version string
			}{
				Title:   "Start Authentication",
				AuthUrl: authURL,
				Version: version.Version(),
			},
		); err != nil {
			fmt.Fprintf(os.Stderr, "Error executing template for /auth handler: %s", err)
		}
	})

	// /callback receives the authorization code from the IdP redirect.
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		queries <- q
		w.Header().Set("Content-Type", "text/html")
		if errParam := q.Get("error"); errParam != "" {
			errDesc := q.Get("error_description")
			w.WriteHeader(http.StatusBadRequest)
			if err := templates.ExecuteTemplate(
				w,
				"autherror",
				struct {
					Title, Error, ErrorDescription, Version string
				}{
					Title:            "Authentication failed",
					Error:            errParam,
					ErrorDescription: errDesc,
					Version:          version.Version(),
				},
			); err != nil {
				fmt.Fprintf(os.Stderr, "Error executing template for /callback error handler: %s", err)
			}
		} else {
			if err := templates.ExecuteTemplate(
				w,
				"authok",
				struct {
					Title, Error, ErrorDescription, Version string
				}{
					Title:   "Authentication Completed",
					Version: version.Version(),
				},
			); err != nil {
				fmt.Fprintf(os.Stderr, "Error executing template for /callback handler: %s", err)
			}
		}
	})

	srv := &http.Server{Handler: mux}

	go func() {
		close(ready)
		if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("local server error: %v", err)
		}
	}()

	// Wait for the server goroutine to be scheduled.
	<-ready
	defer func() {
		_ = srv.Close()
	}()

	// Inform the user and provide the URL for manual entry if the browser fails.
	fmt.Fprintf(os.Stderr, "Please complete authentication in your browser...\n")
	fmt.Fprintf(os.Stderr, "If required you may copy and paste this URL into your browser:\n\n%s\n\n", authURL)

	landingURL := fmt.Sprintf("http://localhost:%d/auth", callbackPort)
	if err := opener.OpenUrl(landingURL); err != nil {
		fmt.Fprintf(os.Stderr, "There was an error opening a browser, please manually visit the provided URL:\n\n%s\n\n", err)
	}

	// Wait for the callback or the 5-minute timeout.
	select {
	case query := <-queries:
		if query.Get("state") != state {
			return nil, fmt.Errorf("state mismatch in callback")
		}
		if errParam := query.Get("error"); errParam != "" {
			return nil, fmt.Errorf("authorization error: %s: %s", errParam, query.Get("error_description"))
		}
		code := query.Get("code")

		// Exchange code for token, again including the resource parameter (RFC 8707).
		token, err := o2c.Exchange(
			ctx,
			code,
			oauth2.VerifierOption(verifier),
			oauth2.SetAuthURLParam("resource", resourceURL),
		)
		if err != nil {
			return nil, fmt.Errorf("token exchange: %w", err)
		}
		return token, nil

	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("authentication timed out after 5 minutes")
		}
		return nil, ctx.Err()
	}
}
