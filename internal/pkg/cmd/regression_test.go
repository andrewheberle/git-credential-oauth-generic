package cmd

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
)

// On a machine without a usable OS keyring (headless Linux without a Secret
// Service, a locked keyring), a registered client must be reused on the next
// run, not registered again. Uses the real client registry against a
// throwaway Git config; not parallel, because it sets the environment and the
// keyring mock.
func TestNoKeyringDoesNotReregister(t *testing.T) {
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(t.TempDir(), "gitconfig"))
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	keyring.MockInitWithError(errors.New("no Secret Service on this machine"))
	t.Cleanup(keyring.MockInit)

	f := newFixture(t)

	for run := 1; run <= 2; run++ {
		var out, errOut bytes.Buffer
		err := execute(context.Background(), []string{"--nopersist", "get"}, env{
			stdin:      strings.NewReader(f.request("https", "authtype")),
			stdout:     &out,
			stderr:     &errOut,
			tokenCache: f.cache,
			clients:    nil, // the real Git config and keyring registry
			httpClient: f.srv.Client(),
			authorize:  f.authz.authorize,
		})
		if err != nil {
			t.Fatalf("run %d: %v (stderr %q)", run, err, errOut.String())
		}
		if out.String() != signedInCredential {
			t.Fatalf("run %d: stdout = %q, want the signed-in credential", run, out.String())
		}
	}

	if *f.registrations != 1 {
		t.Errorf("registered %d clients over two runs, want 1", *f.registrations)
	}
}
