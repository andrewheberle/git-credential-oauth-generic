// Copyright 2025 Andrew Heberle
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// git-credential-oauth-generic is a Git credential helper that authenticates
// to any host supporting RFC 9728 (Protected Resource Metadata), RFC 8414
// (OAuth Authorization Server Metadata), RFC 7591 (Dynamic Client
// Registration), and RFC 8707 (Resource Indicators) via a PKCE authorization
// code flow.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/zalando/go-keyring"
	"golang.org/x/oauth2"
)

var (
	verbose bool
	version = "dev"
)

const (
	keyringService = "git-credential-oauth-generic"
)

func getVersion() string {
	info, ok := debug.ReadBuildInfo()
	if ok && version == "dev" {
		version = info.Main.Version
	}
	return version
}

func printVersion(w io.Writer) {
	fmt.Fprintf(w, "git-credential-oauth-generic %s\n", getVersion())
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
	defer resp.Body.Close()
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
	defer resp.Body.Close()
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
	state := oauth2.GenerateVerifier()
	verifier := oauth2.GenerateVerifier()

	// Listen on the callback port before opening the browser.
	addr := fmt.Sprintf("localhost:%d", callbackPort)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", addr, err)
	}

	queries := make(chan url.Values, 1)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			queries <- r.URL.Query()
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<!DOCTYPE html><html lang="en"><head><title>Git authentication</title>`+
				`<meta name="color-scheme" content="light dark"/></head><body>`+
				`<p>Success. You may close this page and return to Git.</p>`+
				`<p style="font-style:italic">&mdash;git-credential-oauth-generic %s</p>`+
				`</body></html>`, getVersion())
		}),
	}
	go srv.Serve(l)
	defer srv.Close()

	// Build the authorization URL with PKCE and RFC 8707 resource parameter.
	authURL := c.AuthCodeURL(
		state,
		oauth2.S256ChallengeOption(verifier),
		oauth2.SetAuthURLParam("resource", resourceURL),
	)

	fmt.Fprintf(os.Stderr, "Please complete authentication in your browser...\n%s\n", authURL)
	openBrowser(authURL)

	query := <-queries
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
}

// openBrowser attempts to open the given URL in the system browser.
func openBrowser(rawURL string) {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "windows":
		cmd = "rundll32"
		args = []string{"url.dll,FileProtocolHandler", rawURL}
	case "darwin":
		cmd = "open"
		args = []string{rawURL}
	default:
		cmd = "xdg-open"
		args = []string{rawURL}
	}
	if _, err := exec.LookPath(cmd); err == nil {
		if err := exec.Command(cmd, args...).Run(); err != nil {
			fmt.Fprintf(os.Stderr, "unable to open browser using %q: %s\n", cmd, err)
		}
	}
}

func main() {
	ctx := context.Background()
	flag.BoolVar(&verbose, "verbose", false, "log debug information to stderr")
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
	case "store", "erase":
		// Token storage and erasure is delegated to a chained storage helper
		// (e.g. git-credential-cache). Nothing to do here.
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

	// --- Step 1: check for a valid refresh token passed in by the storage helper ---
	var token *oauth2.Token
	if pairs["oauth_refresh_token"] != "" {
		// We need the token endpoint to refresh; we must do discovery first.
		// Fall through to discovery below to obtain it.
		if verbose {
			fmt.Fprintln(os.Stderr, "refresh token available, will attempt refresh after discovery")
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

	// --- Step 3: attempt token refresh if we have a refresh token ---
	if pairs["oauth_refresh_token"] != "" {
		refreshClientID, _ := gitConfig("--get-urlmatch", "credential.oauthClientId", resourceURL)
		refreshClientSecret, _ := keyring.Get(keyringService, fmt.Sprintf("%s.oauthClientSecret", resourceURL))
		c := oauth2.Config{
			ClientID:     refreshClientID,
			ClientSecret: refreshClientSecret,
			Endpoint: oauth2.Endpoint{
				TokenURL:  asMeta.TokenEndpoint,
				AuthStyle: oauth2.AuthStyleInHeader,
			},
		}

		ts := c.TokenSource(ctx, &oauth2.Token{
			RefreshToken: pairs["oauth_refresh_token"],
		})
		refreshed, err := ts.Token()
		if err != nil {
			if verbose {
				fmt.Fprintln(os.Stderr, "token refresh failed:", err)
			}
			// Fall through to full auth flow below.
		} else {
			token = refreshed
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
			// Persist client_id and client_secret in git config so they survive across invocations.
			if err := setGitConfig("--global", fmt.Sprintf("credential.%s.oauthClientId", resourceURL), clientID); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not save client_id to git config: %v\n", err)
			}
			if clientSecret != "" {
				if err := keyring.Set(keyringService, fmt.Sprintf("%s.oauthClientSecret", resourceURL), clientSecret); err != nil {
					fmt.Fprintf(os.Stderr, "warning: could not save client_secret to git config: %v\n", err)
				}
			}
		}

		// --- Step 5: PKCE authorization code flow with RFC 8707 resource parameter ---
		// Read client_secret from git config (may have been stored during registration).
		clientSecret, _ := keyring.Get(keyringService, fmt.Sprintf("%s.oauthClientSecret", resourceURL))
		c := oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
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

	// --- Step 6: output credentials for Git ---
	// Announce authtype capability first as required by the protocol.
	fmt.Println("capability[]=authtype")

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
