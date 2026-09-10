package scanner

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestVendoredFixtureMatchesCanonical guards the copy of the contract-symmetry
// fixture under testdata/. The canonical fixture lives outside this module and
// is shared with the other SDKs; this module carries a byte-identical copy so
// its tests run from a standalone checkout. When the canonical directory is
// reachable, every vendored file must match it exactly. Elsewhere the test
// skips: the copy is then the only source, and there is nothing to compare.
func TestVendoredFixtureMatchesCanonical(t *testing.T) {
	canonicalDir := filepath.Join("..", "..", "..", "testdata", "contract-symmetry")
	if _, err := os.Stat(canonicalDir); err != nil {
		t.Skip("canonical fixture directory not reachable from this checkout")
	}

	vendoredDir := filepath.Join("testdata", "contract-symmetry")
	entries, err := os.ReadDir(vendoredDir)
	if err != nil {
		t.Fatalf("read vendored fixture directory: %v", err)
	}

	compared := 0
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		vendored, err := os.ReadFile(filepath.Join(vendoredDir, e.Name()))
		if err != nil {
			t.Fatalf("read vendored %s: %v", e.Name(), err)
		}
		canonical, err := os.ReadFile(filepath.Join(canonicalDir, e.Name()))
		if err != nil {
			t.Fatalf("read canonical %s: %v", e.Name(), err)
		}
		if !bytes.Equal(vendored, canonical) {
			t.Errorf("%s: vendored copy differs from the canonical fixture; copy the canonical file over it", e.Name())
		}
		compared++
	}
	if compared == 0 {
		t.Fatal("no vendored fixture files found under testdata/contract-symmetry")
	}
}
