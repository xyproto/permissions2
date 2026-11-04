package permissions

import (
	"strings"
	"testing"
)

// The cookie signing secret used to come from the cookie package's
// randomstring stream, which uses math/rand with a fixed seed. Every default
// deployment therefore signed its login cookies with the same secret,
// computable from the public library source. This test fails if the secret
// ever comes from that deterministic stream again.
func TestCookieSecretIsRandom(t *testing.T) {
	const fixedSeedSecret = "BpLnfgDsc2WD8F2qNfHK5a84jjJkwz"
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	a, err := newCookieSecret()
	if err != nil {
		t.Fatal(err)
	}
	b, err := newCookieSecret()
	if err != nil {
		t.Fatal(err)
	}

	if len(a) != 30 || len(b) != 30 {
		t.Fatalf("expected 30-character secrets, got %d and %d", len(a), len(b))
	}
	for _, secret := range []string{a, b} {
		for _, r := range secret {
			if !strings.ContainsRune(alphabet, r) {
				t.Fatalf("secret %q contains a character outside the cookie-friendly alphabet", secret)
			}
		}
		if secret == fixedSeedSecret {
			t.Fatalf("secret must not be the old fixed-seed value %q", fixedSeedSecret)
		}
	}
	if a == b {
		t.Fatal("two generated cookie secrets must differ")
	}
}
