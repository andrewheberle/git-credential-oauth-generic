package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

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
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalln(err)
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

	// --- Step 1: check keyring for a valid cached access token ---
	var token *oauth2.Token
	accessToken := getKeychainItem(resourceURL, "access_token", c.nopersist)
	if accessToken != "" {
		expiry := getKeychainItem(resourceURL, "password_expiry_utc", c.nopersist)
		if expiry != "" {
			var expiryUnix int64
			_, _ = fmt.Sscanf(expiry, "%d", &expiryUnix)
			token = &oauth2.Token{
				AccessToken:  accessToken,
				RefreshToken: getKeychainItem(resourceURL, "refresh_token", c.nopersist),
				Expiry:       time.Unix(expiryUnix, 0),
			}
			if token.Valid() {
				c.logger.Debug("using cached access token from keyring")
			} else {
				// Token exists but is expired; clear it and attempt refresh below.
				c.logger.Debug("cached access token is expired")
				token = nil
			}
		}
	}

	// --- Step 2: RFC 9728 / RFC 8414 discovery ---
	asMeta, err := c.discoverAS(ctx, resourceURL)
	if err != nil {
		c.logger.Debug("discovery failed", "url", resourceURL, "error", err)

		// Host does not support RFC 9728; silently exit so Git falls through
		// to the next credential helper.
		return nil
	}
	c.logger.Debug("discovery completed",
		"authz", asMeta.AuthorizationEndpoint,
		"token", asMeta.TokenEndpoint,
		"registration", asMeta.RegistrationEndpoint,
		"scopes", asMeta.ScopesSupported,
	)

	// --- Step 3: attempt token refresh using keyring refresh token ---
	if token == nil {
		refreshToken := getKeychainItem(resourceURL, "refresh_token", c.nopersist)
		if refreshToken != "" {
			c.logger.Debug("attempting token refresh")
			refreshClientID, _ := gitConfig("--get-urlmatch", "credential.oauthClientId", resourceURL)
			o2c := oauth2.Config{
				ClientID:     refreshClientID,
				ClientSecret: getClientSecret(resourceURL),
				Endpoint: oauth2.Endpoint{
					TokenURL:  asMeta.TokenEndpoint,
					AuthStyle: oauth2.AuthStyleInHeader,
				},
			}
			refreshed, err := o2c.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
			if err != nil {
				c.logger.Debug("token refresh failed", "error", err)

				// Clear stale refresh token and fall through to full auth flow.
				deleteKeychainItem(resourceURL, "refresh_token", c.nopersist)
			} else {
				token = refreshed
			}
		}
	}

	// --- Step 4: dynamic client registration (RFC 7591) if no client_id cached ---
	var clientID string
	if token == nil {
		clientID, _ = gitConfig("--get-urlmatch", "credential.oauthClientId", resourceURL)
		if clientID == "" {
			if asMeta.RegistrationEndpoint == "" {
				fmt.Fprintf(os.Stderr, "host %s requires a client ID but provides no registration endpoint\n", host)
				fmt.Fprintf(os.Stderr, "set one manually: git config --global credential.%s.oauthClientId <ID>\n", resourceURL)
				return nil
			}
			c.logger.Debug("no client_id cached, registering", "endpoint", asMeta.RegistrationEndpoint)

			var clientSecret string
			clientID, clientSecret, err = registerClient(ctx, asMeta.RegistrationEndpoint, c.callbackport)
			if err != nil {
				log.Fatalf("dynamic client registration failed: %v\n", err)
			}
			c.logger.Debug("registered client_id", "client_id", clientID)
			if err := setGitConfig("--global", fmt.Sprintf("credential.%s.oauthClientId", resourceURL), clientID); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not save client_id to git config: %v\n", err)
			}
			if clientSecret != "" {
				if err := setClientSecret(resourceURL, clientSecret); err != nil {
					fmt.Fprintf(os.Stderr, "warning: could not save client_secret to keyring: %v\n", err)
				}
			}
		} else {
			c.logger.Debug("using cached client_id", "client_id", clientID)
		}

		// --- Step 5: PKCE authorization code flow with RFC 8707 resource parameter ---
		o2c := oauth2.Config{
			ClientID:     clientID,
			ClientSecret: getClientSecret(resourceURL),
			Endpoint: oauth2.Endpoint{
				AuthURL:   asMeta.AuthorizationEndpoint,
				TokenURL:  asMeta.TokenEndpoint,
				AuthStyle: oauth2.AuthStyleInHeader,
			},
			RedirectURL: fmt.Sprintf("http://localhost:%d/callback", c.callbackport),
			Scopes:      asMeta.ScopesSupported,
		}
		token, err = c.getToken(ctx, o2c, resourceURL, c.callbackport)
		if err != nil {
			log.Fatalf("authentication failed: %v\n", err)
		}
	}

	c.logger.Debug("got token", "token", token)

	// --- Step 6: persist tokens to keyring ---
	if err := setKeychainItem(resourceURL, "access_token", token.AccessToken, c.nopersist); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not save access_token to keyring: %v\n", err)
	}
	if token.RefreshToken != "" {
		if err := setKeychainItem(resourceURL, "refresh_token", token.RefreshToken, c.nopersist); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not save refresh_token to keyring: %v\n", err)
		}
	}
	if !token.Expiry.IsZero() {
		if err := setKeychainItem(resourceURL, "password_expiry_utc", fmt.Sprintf("%d", token.Expiry.UTC().Unix()), c.nopersist); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not save password_expiry_utc to keyring: %v\n", err)
		}
	}

	// --- Step 7: output credentials for Git ---
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

// protectedResourceMetadata is the RFC 9728 response from
// /.well-known/oauth-protected-resource.
type protectedResourceMetadata struct {
	AuthorizationServers []string `json:"authorization_servers"`
}

// authServerMetadata is the RFC 8414 response from
// /.well-known/oauth-authorization-server.
type authServerMetadata struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	RegistrationEndpoint          string   `json:"registration_endpoint"`
	ScopesSupported               []string `json:"scopes_supported"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
}

// dynamicClientResponse is the RFC 7591 registration response.
type dynamicClientResponse struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// fetchJSON fetches a URL and decodes the JSON response into dst.
func fetchJSON(ctx context.Context, rawURL string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("building request for %s: %w", rawURL, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetching %s: %w", rawURL, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d from %s", resp.StatusCode, rawURL)
	}
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		return fmt.Errorf("decoding response from %s: %w", rawURL, err)
	}
	return nil
}

// discoverAS performs RFC 9728 discovery against the protected resource host,
// then fetches RFC 8414 AS metadata. Returns the metadata and the AS base URL.
func (c *getCommand) discoverAS(ctx context.Context, resourceURL string) (*authServerMetadata, error) {
	u, err := url.Parse(resourceURL)
	if err != nil {
		return nil, fmt.Errorf("parsing resource URL: %w", err)
	}
	// RFC 9728: fetch /.well-known/oauth-protected-resource from the resource host.
	prMetaURL := fmt.Sprintf("%s://%s/.well-known/oauth-protected-resource", u.Scheme, u.Host)
	c.logger.Debug("fetching protected resource metadata", "url", prMetaURL)
	var prMeta protectedResourceMetadata
	if err := fetchJSON(ctx, prMetaURL, &prMeta); err != nil {
		return nil, fmt.Errorf("RFC 9728 discovery failed: %w", err)
	}
	if len(prMeta.AuthorizationServers) == 0 {
		return nil, fmt.Errorf("no authorization_servers in protected resource metadata")
	}
	// Use the first authorization server.
	asBase := prMeta.AuthorizationServers[0]
	c.logger.Debug("authorization server", "url", asBase)
	// RFC 8414: fetch /.well-known/oauth-authorization-server from the AS.
	asParsed, err := url.Parse(asBase)
	if err != nil {
		return nil, fmt.Errorf("parsing AS URL: %w", err)
	}
	asMetaURL := fmt.Sprintf("%s://%s/.well-known/oauth-authorization-server", asParsed.Scheme, asParsed.Host)
	c.logger.Debug("fetching AS metadata", "url", asMetaURL)
	var asMeta authServerMetadata
	if err := fetchJSON(ctx, asMetaURL, &asMeta); err != nil {
		return nil, fmt.Errorf("RFC 8414 AS metadata fetch failed: %w", err)
	}
	return &asMeta, nil
}

// registerClient performs RFC 7591 dynamic client registration against the
// given registration endpoint, requesting a localhost redirect URI on the
// given port.
func registerClient(ctx context.Context, registrationEndpoint string, callbackPort int) (clientID, clientSecret string, err error) {
	redirectURI := fmt.Sprintf("http://localhost:%d/callback", callbackPort)
	body, err := json.Marshal(map[string]any{
		"redirect_uris": []string{redirectURI},
		"client_name":   "git-credential-oauth-generic",
		"grant_types":   []string{"authorization_code", "refresh_token"},
	})
	if err != nil {
		return "", "", fmt.Errorf("encoding registration request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, registrationEndpoint, strings.NewReader(string(body)))
	if err != nil {
		return "", "", fmt.Errorf("building registration request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("registration request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("registration failed (status %d): %s", resp.StatusCode, string(b))
	}
	var result dynamicClientResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", fmt.Errorf("decoding registration response: %w", err)
	}
	if result.ClientID == "" {
		return "", "", fmt.Errorf("registration response missing client_id")
	}
	return result.ClientID, result.ClientSecret, nil
}

// gitConfig runs "git config <args>" and returns trimmed output.
func gitConfig(args ...string) (string, error) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return "", err
	}
	out, err := exec.Command(gitPath, append([]string{"config"}, args...)...).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// setGitConfig runs "git config <args>" discarding output.
func setGitConfig(args ...string) error {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return err
	}
	cmd := exec.Command(gitPath, append([]string{"config"}, args...)...)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
