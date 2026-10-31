package version

import (
	"sync"
	"testing"
)

// Version is called from HTTP handler goroutines (the Authorizer's pages) as
// well as the main goroutine, so it must be safe to call concurrently. Run
// with -race.
func TestVersionConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	results := make([]string, 8)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = Version()
		}()
	}
	wg.Wait()

	for i, v := range results {
		if v == "" || v != results[0] {
			t.Errorf("Version() call %d = %q, want %q", i, v, results[0])
		}
	}
}
