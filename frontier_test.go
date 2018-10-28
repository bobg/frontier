package frontier

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"testing"

	"github.com/bobg/merkle"
)

func TestIsExcluded(t *testing.T) {
	cases := []struct {
		add        []string
		test       string
		wantBool   bool
		wantPrefix string
	}{
		{nil, "abc", true, ""},
		{[]string{"ab"}, "ab", true, "ab"},
		{nil, "abc", true, "ab"},
		{nil, "a", false, ""},
		{nil, "ac", false, ""},
		{nil, "b", false, ""},
		{[]string{"ba"}, "b", false, ""},
		{nil, "ba", true, "ba"},
		{nil, "bac", true, "ba"},
	}

	var f Frontier

	for i, c := range cases {
		for _, a := range c.add {
			f.Exclude([]byte(a))
		}
		gotPrefix, gotBool := f.Check([]byte(c.test))
		if gotBool != c.wantBool {
			t.Errorf("case %d: got %v, want %v", i+1, gotBool, c.wantBool)
			continue
		}
		if gotBool {
			if !bytes.Equal(gotPrefix, []byte(c.wantPrefix)) {
				t.Errorf("case %d: got prefix %s, want %s", i+1, string(gotPrefix), c.wantPrefix)
			}
		}
	}
}

func TestText(t *testing.T) {
	f, err := os.Open("testdata/udhr.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	const chunksize = 256

	hasher := sha256.New()
	var frontier Frontier

	for {
		var buf [chunksize]byte
		n, err := io.ReadFull(f, buf[:])
		if err == io.EOF {
			// "The error is EOF only if no bytes were read."
			break
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			t.Fatal(err)
		}
		frontier.Exclude(merkle.LeafHash(hasher, nil, buf[:n]))
	}

	const frontierWantHex = "d94a741e17fbec53260720e4e1411578f826036755d34cf060e6291f0d3d3439"
	frontierTree := frontier.MerkleTree(sha256.New())
	frontierRoot := frontierTree.Root()
	frontierRootHex := hex.EncodeToString(frontierRoot)
	if frontierRootHex != frontierWantHex {
		t.Errorf("frontier: got %s, want %s", frontierRootHex, frontierWantHex)
	}
}

func BenchmarkTextFrontier(b *testing.B) {
	for i := 0; i < b.N; i++ {
		func() {
			helper(b)
		}()
	}
}

func BenchmarkTextFrontierMerkleRoot(b *testing.B) {
	for i := 0; i < b.N; i++ {
		func() {
			frontier := helper(b)
			frontierTree := frontier.MerkleTree(sha256.New())
			frontierTree.Root()
		}()
	}
}

func helper(b *testing.B) *Frontier {
	f, err := os.Open("testdata/udhr.txt")
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()

	const chunksize = 256
	var frontier Frontier
	for {
		var buf [chunksize]byte
		n, err := io.ReadFull(f, buf[:])
		if err == io.EOF {
			// "The error is EOF only if no bytes were read."
			break
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			b.Fatal(err)
		}
		frontier.Exclude(buf[:n])
	}
	return &frontier
}
