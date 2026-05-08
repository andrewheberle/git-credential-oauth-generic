// git-credential-oauth-generic is a Git credential helper that authenticates
// to any host supporting RFC 9728 (Protected Resource Metadata), RFC 8414
// (OAuth Authorization Server Metadata), RFC 7591 (Dynamic Client
// Registration), and RFC 8707 (Resource Indicators) via a PKCE authorization
// code flow.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/andrewheberle/opener"
	"github.com/zalando/go-keyring"
)

var (
	verbose   bool
	nopersist bool
	version   = "dev"
)

func getVersion() string {
	info, ok := debug.ReadBuildInfo()
	if ok && version == "dev" {
		version = info.Main.Version
	}
	return version
}

func printVersion(w io.Writer) {
	_, _ = fmt.Fprintf(w, "git-credential-oauth-generic %s\n", getVersion())
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
func discoverAS(ctx context.Context, resourceURL string) (*authServerMetadata, error) {
	u, err := url.Parse(resourceURL)
	if err != nil {
		return nil, fmt.Errorf("parsing resource URL: %w", err)
	}
	// RFC 9728: fetch /.well-known/oauth-protected-resource from the resource host.
	prMetaURL := fmt.Sprintf("%s://%s/.well-known/oauth-protected-resource", u.Scheme, u.Host)
	if verbose {
		fmt.Fprintf(os.Stderr, "fetching protected resource metadata: %s\n", prMetaURL)
	}
	var prMeta protectedResourceMetadata
	if err := fetchJSON(ctx, prMetaURL, &prMeta); err != nil {
		return nil, fmt.Errorf("RFC 9728 discovery failed: %w", err)
	}
	if len(prMeta.AuthorizationServers) == 0 {
		return nil, fmt.Errorf("no authorization_servers in protected resource metadata")
	}
	// Use the first authorization server.
	asBase := prMeta.AuthorizationServers[0]
	if verbose {
		fmt.Fprintf(os.Stderr, "authorization server: %s\n", asBase)
	}
	// RFC 8414: fetch /.well-known/oauth-authorization-server from the AS.
	asParsed, err := url.Parse(asBase)
	if err != nil {
		return nil, fmt.Errorf("parsing AS URL: %w", err)
	}
	asMetaURL := fmt.Sprintf("%s://%s/.well-known/oauth-authorization-server", asParsed.Scheme, asParsed.Host)
	if verbose {
		fmt.Fprintf(os.Stderr, "fetching AS metadata: %s\n", asMetaURL)
	}
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

// getToken performs the PKCE authorization code flow, opening the browser and
// listening for the callback on the given port. The resource parameter (RFC
// 8707) is appended to the authorization URL.
func getToken(ctx context.Context, c oauth2.Config, resourceURL string, callbackPort int) (*oauth2.Token, error) {
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
	authURL := c.AuthCodeURL(
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
		fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
	<title>git-credential-oauth-generic: Start Authentication</title>
	<meta name="color-scheme" content="light dark"/>
	<style>
		body { font-family: sans-serif; max-width: 600px; margin: 2em auto; padding: 0 1em; }
		.url-box { background: #f4f4f4; border: 1px solid #ccc; border-radius: 4px; padding: 0.75em; word-break: break-all; font-family: monospace; font-size: 0.85em; margin: 1em 0; }
		@media (prefers-color-scheme: dark) { .url-box { background: #2a2a2a; border-color: #555; } }
		.continue { display: inline-block; margin-top: 0.5em; padding: 0.5em 1.5em; background: #0070f3; color: white; text-decoration: none; border-radius: 4px; }
		.continue:hover { background: #005bb5; }
	</style>
</head>
<body>
	<h2>git-credential-oauth-generic</h2>
	<p>You are about to be redirected to your identity provider to authenticate Git.</p>
	<p>If this browser is signed into the wrong account, copy the URL below and
	open it in the correct browser profile instead:</p>
	<div class="url-box">%s</div>
	<a class="continue" href="%s">Continue &rarr;</a>
	<p style="font-style:italic; margin-top:2em">- git-credential-oauth-generic %s</p>
</body>
</html>`, authURL, authURL, getVersion())
	})

	// /callback receives the authorization code from the IdP redirect.
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		queries <- q
		w.Header().Set("Content-Type", "text/html")
		if errParam := q.Get("error"); errParam != "" {
			errDesc := q.Get("error_description")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `<!DOCTYPE html><html lang="en"><head><title>git-credential-oauth-generic: Authentication failed</title>`+
				`<meta name="color-scheme" content="light dark"/></head><body>`+
				`<p><strong>Authentication failed:</strong> %s</p>`+
				`<p>%s</p>`+
				`<p style="font-style:italic">- git-credential-oauth-generic %s</p>`+
				`</body></html>`, errParam, errDesc, getVersion())
		} else {
			fmt.Fprintf(w, `<!DOCTYPE html><html lang="en"><head><title>Git authentication</title>`+
				`<meta name="color-scheme" content="light dark"/></head><body>`+
				`<p>Success. You may close this page and return to Git.</p>`+
				`<p style="font-style:italic">- git-credential-oauth-generic %s</p>`+
				`</body></html>`, getVersion())
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
		token, err := c.Exchange(
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

const (
	keyringService = "git-credential-oauth-generic"
)

// getClientSecret retrieves the client secret from the OS keyring for the
// given resource URL. Returns empty string if not found.
func getClientSecret(resourceURL string) string {
	return getKeychainItem(resourceURL, "client_secret")
}

// setClientSecret stores the client secret in the OS keyring for the given
// resource URL.
func setClientSecret(resourceURL, secret string) error {
	return keyring.Set(keyringService, resourceURL+":client_secret", secret)
}

// getKeychainItem retrieves a value from the OS keyring for the given resource URL
// and item name.
func getKeychainItem(resourceURL, item string) string {
	// no-op for anything except the "client_secret" when nopersist set
	if item != "client_secret" && nopersist {
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
func setKeychainItem(resourceURL, item, value string) error {
	// no-op for anything except the "client_secret" when nopersist set
	if item != "client_secret" && nopersist {
		return nil
	}

	return keyring.Set(keyringService, resourceURL+":"+item, value)
}

// deleteKeychainItem removes a value from the OS keyring for the given resource
// URL and item name.
func deleteKeychainItem(resourceURL, item string) {
	// no-op for anything except the "client_secret" when nopersist set
	if item != "client_secret" && nopersist {
		return
	}

	_ = keyring.Delete(keyringService, resourceURL+":"+item)
}

func main() {
	ctx := context.Background()
	flag.BoolVar(&verbose, "verbose", false, "log debug information to stderr")
	flag.BoolVar(&nopersist, "nopersist", false, "rely on another helper to persist credentials")
	callbackPort := flag.Int("port", 8400, "localhost port for OAuth callback")
	flag.Usage = func() {
		printVersion(os.Stderr)
		fmt.Fprintln(os.Stderr, "usage: git-credential-oauth-generic [<options>] <action>")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Actions:")
		fmt.Fprintln(os.Stderr, "  get            Generate credential [called by Git]")
		fmt.Fprintln(os.Stderr, "  store          No-op [called by Git]")
		fmt.Fprintln(os.Stderr, "  erase          No-op [called by Git]")
		fmt.Fprintln(os.Stderr, "  version        Print version")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "See also https://github.com/andrewheberle/git-credential-oauth-generic")
	}
	flag.Parse()
	args := flag.Args()
	if len(args) != 1 {
		flag.Usage()
		os.Exit(2)
	}

	switch args[0] {
	case "store":
		// Token storage and erasure is delegated to a chained storage helper
		// (e.g. git-credential-cache). Nothing to do here.
		return

	case "erase":
		// no-op if we do no persist data
		if nopersist {
			return
		}

		// Remove stored tokens from the keyring so the next get triggers a
		// fresh OAuth flow. client_id (git config) and client_secret (keyring)
		// are left intact.
		input, err := io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalln(err)
		}
		pairs := parse(string(input))
		host := pairs["host"]
		protocol := pairs["protocol"]
		if protocol == "https" && host != "" {
			resourceURL := fmt.Sprintf("https://%s", host)
			deleteKeychainItem(resourceURL, "access_token")
			deleteKeychainItem(resourceURL, "refresh_token")
			deleteKeychainItem(resourceURL, "password_expiry_utc")
			if verbose {
				fmt.Fprintf(os.Stderr, "erased tokens for %s from keyring\n", resourceURL)
			}
		}
		return

	case "version":
		printVersion(os.Stdout)
		return

	case "capability":
		// https://git-scm.com/docs/git-credential#CAPA-IOFMT
		fmt.Println("version 0")
		fmt.Println("capability authtype")
		return

	case "get":
		if verbose {
			printVersion(os.Stderr)
		}
	default:
		flag.Usage()
		os.Exit(2)
	}

	// --- get action ---

	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalln(err)
	}
	pairs := parse(string(input))
	if verbose {
		fmt.Fprintln(os.Stderr, "input:", pairs)
	}

	protocol := pairs["protocol"]
	host := pairs["host"]
	if protocol == "" || host == "" {
		fmt.Fprintln(os.Stderr, "missing protocol or host in input")
		return
	}
	if protocol != "https" {
		// Only HTTPS makes sense for OAuth.
		if verbose {
			fmt.Fprintf(os.Stderr, "skipping non-https protocol %q\n", protocol)
		}
		return
	}

	resourceURL := fmt.Sprintf("https://%s", host)

	// --- Step 1: check keyring for a valid cached access token ---
	var token *oauth2.Token
	accessToken := getKeychainItem(resourceURL, "access_token")
	if accessToken != "" {
		expiry := getKeychainItem(resourceURL, "password_expiry_utc")
		if expiry != "" {
			var expiryUnix int64
			fmt.Sscanf(expiry, "%d", &expiryUnix)
			token = &oauth2.Token{
				AccessToken:  accessToken,
				RefreshToken: getKeychainItem(resourceURL, "refresh_token"),
				Expiry:       time.Unix(expiryUnix, 0),
			}
			if token.Valid() {
				if verbose {
					fmt.Fprintln(os.Stderr, "using cached access token from keyring")
				}
			} else {
				// Token exists but is expired; clear it and attempt refresh below.
				if verbose {
					fmt.Fprintln(os.Stderr, "cached access token is expired")
				}
				token = nil
			}
		}
	}

	// --- Step 2: RFC 9728 / RFC 8414 discovery ---
	asMeta, err := discoverAS(ctx, resourceURL)
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "discovery failed for %s: %v\n", resourceURL, err)
		}
		// Host does not support RFC 9728; silently exit so Git falls through
		// to the next credential helper.
		return
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "AS metadata: authz=%s token=%s registration=%s scopes=%v\n",
			asMeta.AuthorizationEndpoint, asMeta.TokenEndpoint, asMeta.RegistrationEndpoint, asMeta.ScopesSupported)
	}

	// --- Step 3: attempt token refresh using keyring refresh token ---
	if token == nil {
		refreshToken := getKeychainItem(resourceURL, "refresh_token")
		if refreshToken != "" {
			if verbose {
				fmt.Fprintln(os.Stderr, "attempting token refresh")
			}
			refreshClientID, _ := gitConfig("--get-urlmatch", "credential.oauthClientId", resourceURL)
			c := oauth2.Config{
				ClientID:     refreshClientID,
				ClientSecret: getClientSecret(resourceURL),
				Endpoint: oauth2.Endpoint{
					TokenURL:  asMeta.TokenEndpoint,
					AuthStyle: oauth2.AuthStyleInHeader,
				},
			}
			refreshed, err := c.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
			if err != nil {
				if verbose {
					fmt.Fprintln(os.Stderr, "token refresh failed:", err)
				}
				// Clear stale refresh token and fall through to full auth flow.
				deleteKeychainItem(resourceURL, "refresh_token")
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
				return
			}
			if verbose {
				fmt.Fprintf(os.Stderr, "no client_id cached, registering with %s\n", asMeta.RegistrationEndpoint)
			}
			var clientSecret string
			clientID, clientSecret, err = registerClient(ctx, asMeta.RegistrationEndpoint, *callbackPort)
			if err != nil {
				log.Fatalf("dynamic client registration failed: %v\n", err)
			}
			if verbose {
				fmt.Fprintf(os.Stderr, "registered client_id: %s\n", clientID)
			}
			if err := setGitConfig("--global", fmt.Sprintf("credential.%s.oauthClientId", resourceURL), clientID); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not save client_id to git config: %v\n", err)
			}
			if clientSecret != "" {
				if err := setClientSecret(resourceURL, clientSecret); err != nil {
					fmt.Fprintf(os.Stderr, "warning: could not save client_secret to keyring: %v\n", err)
				}
			}
		} else {
			if verbose {
				fmt.Fprintf(os.Stderr, "using cached client_id: %s\n", clientID)
			}
		}

		// --- Step 5: PKCE authorization code flow with RFC 8707 resource parameter ---
		c := oauth2.Config{
			ClientID:     clientID,
			ClientSecret: getClientSecret(resourceURL),
			Endpoint: oauth2.Endpoint{
				AuthURL:   asMeta.AuthorizationEndpoint,
				TokenURL:  asMeta.TokenEndpoint,
				AuthStyle: oauth2.AuthStyleInHeader,
			},
			RedirectURL: fmt.Sprintf("http://localhost:%d/callback", *callbackPort),
			Scopes:      asMeta.ScopesSupported,
		}
		token, err = getToken(ctx, c, resourceURL, *callbackPort)
		if err != nil {
			log.Fatalf("authentication failed: %v\n", err)
		}
	}

	if verbose {
		fmt.Fprintln(os.Stderr, "token:", token)
	}

	// --- Step 6: persist tokens to keyring ---
	if err := setKeychainItem(resourceURL, "access_token", token.AccessToken); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not save access_token to keyring: %v\n", err)
	}
	if token.RefreshToken != "" {
		if err := setKeychainItem(resourceURL, "refresh_token", token.RefreshToken); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not save refresh_token to keyring: %v\n", err)
		}
	}
	if !token.Expiry.IsZero() {
		if err := setKeychainItem(resourceURL, "password_expiry_utc", fmt.Sprintf("%d", token.Expiry.UTC().Unix())); err != nil {
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
		return
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
	if verbose {
		fmt.Fprintln(os.Stderr, "output:", output)
	}
	for k, v := range output {
		fmt.Printf("%s=%s\n", k, v)
	}
}
