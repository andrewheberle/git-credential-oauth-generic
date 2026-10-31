// Package authorize implements the Authorizer: the interactive step of
// Credential acquisition, an OAuth PKCE authorization code flow in the user's
// browser with the redirect caught by a short-lived server on localhost.
package authorize

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/andrewheberle/git-credential-oauth-generic/internal/pkg/version"
	"github.com/andrewheberle/opener"
	"golang.org/x/oauth2"
)

// DefaultTimeout is how long the user has to complete sign-in, allowing for
// browser profile switching, copying the URL by hand, or MFA challenges.
const DefaultTimeout = 5 * time.Minute

// shutdownGrace bounds how long the local server waits for the final result
// page to be delivered before it is closed.
const shutdownGrace = 2 * time.Second

//go:embed pages/*.tmpl
var pageFS embed.FS

// pages holds one parsed template set per page, each executed as "page".
var pages = func() map[string]*template.Template {
	m := map[string]*template.Template{}
	for _, name := range []string{"start", "authok", "autherror", "notice"} {
		m[name] = template.Must(template.ParseFS(pageFS, "pages/page.tmpl", "pages/"+name+".tmpl"))
	}
	return m
}()

// pageData is the data every page template is executed with. html/template
// escapes all of it, since Error and ErrorDescription come from the callback
// query string.
type pageData struct {
	Title, AuthURL, Error, ErrorDescription, Version string
}

// Loopback is an Authorizer that sends the user's browser to the
// authorization server and receives the redirect on the localhost address of
// the configured redirect URI. The zero value is ready to use.
type Loopback struct {
	// Open opens a URL in the user's browser. Defaults to opener.OpenUrl.
	Open func(url string) error

	// Out receives the instructions shown to the user, including the
	// authorization URL to copy if the browser cannot be opened. Defaults to
	// os.Stderr.
	Out io.Writer

	// Logger receives diagnostics. Defaults to discarding them.
	Logger *slog.Logger

	// Timeout bounds the whole sign-in. Defaults to DefaultTimeout.
	Timeout time.Duration
}

// result is the outcome of the one callback that settles a sign-in.
type result struct {
	token *oauth2.Token
	err   error
}

// Authorize runs the authorization code flow for cfg with PKCE, passing
// resourceURL as the RFC 8707 resource parameter, and returns the token.
//
// It listens on the host and port of cfg.RedirectURL and opens a landing page
// that links to the authorization server. Callbacks whose state does not
// match are answered with an error page and otherwise ignored, so a stale tab
// or a stray request cannot end the sign-in. The first callback with the
// right state settles it: an error from the authorization server, a missing
// code or a failed code exchange fails it; otherwise the token is returned.
// The browser is shown the real outcome, and any later callback is told the
// sign-in has already completed.
//
// The context should carry the HTTP client for the code exchange (see
// oauth2.HTTPClient), as Credential acquisition provides.
func (l *Loopback) Authorize(ctx context.Context, cfg oauth2.Config, resourceURL string) (*oauth2.Token, error) {
	open, out, logger, timeout := l.Open, l.Out, l.Logger, l.Timeout
	if open == nil {
		open = opener.OpenUrl
	}
	if out == nil {
		out = os.Stderr
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	redirect, err := url.Parse(cfg.RedirectURL)
	if err != nil || redirect.Host == "" {
		return nil, fmt.Errorf("invalid redirect URL %q", cfg.RedirectURL)
	}
	callbackPath := redirect.Path
	if callbackPath == "" {
		callbackPath = "/"
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	state := oauth2.GenerateVerifier()
	verifier := oauth2.GenerateVerifier()

	// Listen before opening the browser so the redirect cannot arrive early.
	listener, err := net.Listen("tcp", redirect.Host)
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", redirect.Host, err)
	}

	authURL := cfg.AuthCodeURL(
		state,
		oauth2.S256ChallengeOption(verifier),
		oauth2.SetAuthURLParam("resource", resourceURL),
	)

	done := make(chan result, 1)
	var (
		mu      sync.Mutex
		settled bool
	)

	render := func(w http.ResponseWriter, status int, name string, data pageData) {
		data.Version = version.Version()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		if err := pages[name].ExecuteTemplate(w, "page", data); err != nil {
			logger.Error("could not render page", "page", name, "error", err)
		}
	}

	mux := http.NewServeMux()

	// The landing page shows the authorization URL as a copyable link and a
	// Continue button, so the user can open it in the right browser profile.
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		render(w, http.StatusOK, "start", pageData{Title: "Start Authentication", AuthURL: authURL})
	})

	mux.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		mu.Lock()
		if settled {
			mu.Unlock()
			render(w, http.StatusConflict, "notice", pageData{
				Title:            "Sign-in already completed",
				ErrorDescription: "This sign-in has already finished. You may close this page.",
			})
			return
		}
		if q.Get("state") != state {
			mu.Unlock()
			logger.Warn("ignoring callback with unexpected state")
			render(w, http.StatusBadRequest, "notice", pageData{
				Title:            "Unexpected sign-in response",
				ErrorDescription: "This response does not belong to the sign-in in progress and was ignored. If you started a new sign-in, use the newest browser tab.",
			})
			return
		}
		settled = true
		mu.Unlock()

		token, status, page, data, err := l.complete(ctx, cfg, q, verifier, resourceURL)
		render(w, status, page, data)
		done <- result{token: token, err: err}
	})

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("local callback server failed", "error", err)
		}
	}()
	defer func() {
		// Shutdown, not Close, so the final result page is delivered.
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	_, _ = fmt.Fprintf(out, "Please complete authentication in your browser...\n")
	_, _ = fmt.Fprintf(out, "If required you may copy and paste this URL into your browser:\n\n%s\n\n", authURL)

	landingURL := (&url.URL{Scheme: "http", Host: redirect.Host, Path: "/auth"}).String()
	if err := open(landingURL); err != nil {
		logger.Debug("could not open browser", "error", err)
		_, _ = fmt.Fprintf(out, "Could not open a browser (%v); please open the URL above manually.\n\n", err)
	}

	select {
	case res := <-done:
		return res.token, res.err
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("authentication timed out after %s", timeout)
		}
		return nil, ctx.Err()
	}
}

// complete settles a sign-in from a callback with the right state: it checks
// for an authorization error, exchanges the code, and says which page to show.
func (l *Loopback) complete(ctx context.Context, cfg oauth2.Config, q url.Values, verifier, resourceURL string) (*oauth2.Token, int, string, pageData, error) {
	if errParam := q.Get("error"); errParam != "" {
		desc := q.Get("error_description")
		return nil, http.StatusBadRequest, "autherror",
			pageData{Title: "Authentication failed", Error: errParam, ErrorDescription: desc},
			fmt.Errorf("authorization error: %s: %s", errParam, desc)
	}

	code := q.Get("code")
	if code == "" {
		return nil, http.StatusBadRequest, "autherror",
			pageData{Title: "Authentication failed", Error: "missing code", ErrorDescription: "The authorization server did not return an authorization code."},
			errors.New("authorization response missing code")
	}

	// Exchange the code, again including the resource parameter (RFC 8707).
	token, err := cfg.Exchange(ctx, code,
		oauth2.VerifierOption(verifier),
		oauth2.SetAuthURLParam("resource", resourceURL),
	)
	if err != nil {
		return nil, http.StatusBadGateway, "autherror",
			pageData{Title: "Authentication failed", Error: "token exchange failed", ErrorDescription: err.Error()},
			fmt.Errorf("token exchange: %w", err)
	}

	return token, http.StatusOK, "authok", pageData{Title: "Authentication Completed"}, nil
}
