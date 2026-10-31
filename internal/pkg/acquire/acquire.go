// Package acquire implements Credential acquisition: turning a resource URL
// into an OAuth access token Git can use, by reusing a cached token,
// refreshing it, or registering a client and sending the user through the
// browser, in that order of preference.
package acquire

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

var (
	// ErrNotOAuthHost means the host does not advertise OAuth protected
	// resource metadata, so this helper has nothing to offer and Git should
	// fall through to the next credential helper.
	ErrNotOAuthHost = errors.New("host does not advertise OAuth protected resource metadata")

	// ErrDiscovery means the host is OAuth-protected (or could not be
	// reached to find out) but its authorization server could not be
	// discovered: a network error, timeout or server error, metadata that
	// can't be read, or metadata for a different resource or issuer. Unlike
	// ErrNotOAuthHost it should be reported to the user.
	ErrDiscovery = errors.New("OAuth discovery failed")

	// ErrClientIDRequired means no client is registered for the resource and
	// the authorization server offers no dynamic client registration, so a
	// client ID must be configured by hand.
	ErrClientIDRequired = errors.New("authorization server requires a client ID but offers no registration endpoint")
)

// defaultHTTPTimeout bounds discovery, registration and refresh requests. The
// browser flow has its own, longer timeout.
const defaultHTTPTimeout = 30 * time.Second

// TokenCache stores the tokens obtained for a resource URL between runs.
type TokenCache interface {
	Load(ctx context.Context, resourceURL string) (*oauth2.Token, error)
	Save(ctx context.Context, resourceURL string, token *oauth2.Token) error
	Erase(ctx context.Context, resourceURL string)
}

// Client is a Registered client: the OAuth client this helper is known as to
// an authorization server. Secret is empty for public clients. RedirectURI is
// the redirect URI it was registered with; it is empty for a client ID set by
// hand or registered by an earlier version.
type Client struct {
	ID          string
	Secret      string
	RedirectURI string
}

// ClientRegistry stores the Registered client for a resource URL. Lookup
// returns a zero Client when none is registered, and an error only when the
// store cannot be read, in which case Credential acquisition stops rather than
// registering a replacement.
type ClientRegistry interface {
	Lookup(ctx context.Context, resourceURL string) (Client, error)
	Remember(ctx context.Context, resourceURL string, client Client) error
}

// Authorize is the Authorizer: it obtains a token interactively for the given
// OAuth configuration, passing resourceURL as the RFC 8707 resource parameter.
// The context carries the HTTP client to use for the code exchange (see
// oauth2.HTTPClient).
type Authorize func(ctx context.Context, cfg oauth2.Config, resourceURL string) (*oauth2.Token, error)

// Config holds the dependencies of an Acquirer.
type Config struct {
	Cache     TokenCache
	Clients   ClientRegistry
	Authorize Authorize

	// HTTPClient is used for discovery, registration and token requests. If
	// nil, a client with a 30-second timeout is used.
	HTTPClient *http.Client

	// CallbackPort is the localhost port of the redirect URI that is
	// registered and used for the authorization code flow.
	CallbackPort int

	// Logger receives debug detail and warnings. If nil, nothing is logged.
	Logger *slog.Logger
}

// Acquirer performs Credential acquisition.
type Acquirer struct {
	cache        TokenCache
	clients      ClientRegistry
	authorize    Authorize
	httpClient   *http.Client
	callbackPort int
	logger       *slog.Logger
}

// New returns an Acquirer using the given dependencies.
func New(cfg Config) *Acquirer {
	a := &Acquirer{
		cache:        cfg.Cache,
		clients:      cfg.Clients,
		authorize:    cfg.Authorize,
		httpClient:   cfg.HTTPClient,
		callbackPort: cfg.CallbackPort,
		logger:       cfg.Logger,
	}
	if a.httpClient == nil {
		a.httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	if a.logger == nil {
		a.logger = slog.New(slog.DiscardHandler)
	}
	return a
}

// Acquire returns an access token for resourceURL. In order, it:
//
//  1. returns a still-valid cached token, without any network requests;
//  2. discovers the authorization server (RFC 9728, RFC 8414), returning
//     ErrNotOAuthHost if the host does not support it, or ErrDiscovery if
//     discovery fails;
//  3. refreshes the cached refresh token, if there is one and a Registered
//     client to refresh it with, erasing the cache entry if that fails;
//  4. registers a client (RFC 7591) if none is registered, returning
//     ErrClientIDRequired if the server does not support registration;
//  5. runs the Authorizer.
//
// A newly obtained token is saved to the Token cache; failing to save is
// logged as a warning and does not fail the call.
func (a *Acquirer) Acquire(ctx context.Context, resourceURL string) (*oauth2.Token, error) {
	cached, err := a.cache.Load(ctx, resourceURL)
	if err != nil {
		a.logger.Debug("could not read token cache", "error", err)
		cached = nil
	}
	if cached.Valid() {
		a.logger.Debug("using cached access token")
		return cached, nil
	}

	meta, err := a.discover(ctx, resourceURL)
	if err != nil {
		return nil, err
	}
	a.logger.Debug("discovery completed",
		"authz", meta.AuthorizationEndpoint,
		"token", meta.TokenEndpoint,
		"registration", meta.RegistrationEndpoint,
		"scopes", meta.ScopesSupported,
	)

	// Token requests made by the oauth2 package use our HTTP client.
	ctx = context.WithValue(ctx, oauth2.HTTPClient, a.httpClient)

	client, err := a.clients.Lookup(ctx, resourceURL)
	if err != nil {
		return nil, fmt.Errorf("looking up registered client: %w", err)
	}

	if cached != nil && cached.RefreshToken != "" && client.ID != "" {
		token, err := a.refresh(ctx, meta, client, cached.RefreshToken)
		if err == nil {
			a.save(ctx, resourceURL, token)
			return token, nil
		}
		a.logger.Debug("token refresh failed", "error", err)
		// Clear the stale entry and fall through to the full flow.
		a.cache.Erase(ctx, resourceURL)
	}

	if a.needsRegistration(client, meta) {
		if meta.RegistrationEndpoint == "" {
			return nil, ErrClientIDRequired
		}
		a.logger.Debug("registering client", "endpoint", meta.RegistrationEndpoint)
		client, err = a.register(ctx, meta.RegistrationEndpoint)
		if err != nil {
			return nil, fmt.Errorf("dynamic client registration: %w", err)
		}
		a.logger.Debug("registered client", "client_id", client.ID)
		if err := a.clients.Remember(ctx, resourceURL, client); err != nil {
			a.logger.Warn("could not save registered client", "error", err)
		}
	} else {
		a.logger.Debug("using registered client", "client_id", client.ID)
	}

	token, err := a.authorize(ctx, oauth2.Config{
		ClientID:     client.ID,
		ClientSecret: client.Secret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   meta.AuthorizationEndpoint,
			TokenURL:  meta.TokenEndpoint,
			AuthStyle: oauth2.AuthStyleInHeader,
		},
		RedirectURL: a.redirectURL(),
		Scopes:      meta.ScopesSupported,
	}, resourceURL)
	if err != nil {
		return nil, fmt.Errorf("authentication: %w", err)
	}

	a.save(ctx, resourceURL, token)
	return token, nil
}

// needsRegistration reports whether a new client must be registered: when none
// is registered, or when the registered one was registered with a different
// redirect URI (the callback port changed) and the server can register a new
// one. A client with no recorded redirect URI (set by hand, or registered by
// an earlier version) is never replaced.
func (a *Acquirer) needsRegistration(client Client, meta *authServerMetadata) bool {
	if client.ID == "" {
		return true
	}
	if client.RedirectURI == "" || client.RedirectURI == a.redirectURL() {
		return false
	}
	if meta.RegistrationEndpoint == "" {
		a.logger.Warn("registered client was registered with a different redirect URI and the server offers no registration; sign-in may fail",
			"registered", client.RedirectURI, "current", a.redirectURL())
		return false
	}
	a.logger.Debug("callback redirect URI changed; registering a new client",
		"registered", client.RedirectURI, "current", a.redirectURL())
	return true
}

// refresh exchanges refreshToken for a new token at the token endpoint.
func (a *Acquirer) refresh(ctx context.Context, meta *authServerMetadata, client Client, refreshToken string) (*oauth2.Token, error) {
	a.logger.Debug("attempting token refresh")
	cfg := oauth2.Config{
		ClientID:     client.ID,
		ClientSecret: client.Secret,
		Endpoint: oauth2.Endpoint{
			TokenURL:  meta.TokenEndpoint,
			AuthStyle: oauth2.AuthStyleInHeader,
		},
	}
	return cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
}

// save stores token in the Token cache, warning on failure.
func (a *Acquirer) save(ctx context.Context, resourceURL string, token *oauth2.Token) {
	if err := a.cache.Save(ctx, resourceURL, token); err != nil {
		a.logger.Warn("could not save tokens to token cache", "error", err)
	}
}

func (a *Acquirer) redirectURL() string {
	return fmt.Sprintf("http://localhost:%d/callback", a.callbackPort)
}
