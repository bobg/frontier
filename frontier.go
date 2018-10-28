package frontier

import (
	"hash"

	"github.com/bobg/merkle"
)

// Frontier is a trie that contains the shortest bytewise prefixes of all strings _not_ in a set.
type Frontier struct {
	top tier
}

// Exclude adds str to f.
// (It's called Exclude because this means str is excluded from f's complement set.)
func (f *Frontier) Exclude(str []byte) {
	if len(str) == 0 {
		return
	}
	if f.top == nil {
		f.top = &unitier{b: str[0]}
	}
	f.top = f.top.set(str, zerotier{})
}

// Check tells whether str has a prefix in f.
// It returns the prefix and true if so,
// false if not.
func (f *Frontier) Check(str []byte) ([]byte, bool) {
	if f.top == nil || f.top.empty() {
		return nil, true
	}
	return check(f.top, str, nil)
}

func check(tier tier, str, prefix []byte) ([]byte, bool) {
	if len(str) == 0 {
		return prefix, tier.empty()
	}
	subtier := tier.get(str[0])
	if subtier == nil {
		return prefix, tier.empty()
	}
	return check(subtier, str[1:], append(prefix, str[0]))
}

// MerkleTree produces the merkle hash tree of an in-order, depth-first walk of the frontier.
// This can be used to prove in zero knowledge that a string is not in f's complement set
// (by proving that a prefix of that string is in f).
func (f *Frontier) MerkleTree(hasher hash.Hash) *merkle.Tree {
	m := merkle.NewTree(hasher)
	f.Walk(func(str []byte) {
		m.Add(str)
	})
	return m
}

// MerkleProofTree produces the a merkle hash tree of an in-order, depth-first walk of the frontier
// that is able to prove compactly that it contains the given reference string.
func (f *Frontier) MerkleProofTree(hasher hash.Hash, ref []byte) *merkle.Tree {
	m := merkle.NewProofTree(hasher, ref)
	f.Walk(func(str []byte) {
		m.Add(str)
	})
	return m
}

// Walk performs an in-order depth-first traversal of f,
// calling a callback on each string.
// The callback must make its own copy of the string if needed;
// Walk reuses the space on each callback call.
func (f *Frontier) Walk(fn func(str []byte)) {
	walkHelper(f.top, fn, nil)
}

func walkHelper(tier tier, fn func(str []byte), prefix []byte) {
	if tier == nil {
		return
	}
	for i := 0; i < 256; i++ {
		s := append(prefix, byte(i))
		if subtier := tier.get(byte(i)); subtier != nil {
			walkHelper(subtier, fn, s)
		} else {
			fn(s)
		}
	}
}

type tier interface {
	get(byte) tier
	set([]byte, tier) tier
	empty() bool
}

type zerotier struct{}

func (z zerotier) get(byte) tier {
	return nil
}

func (z zerotier) set(str []byte, subtier tier) tier {
	u := &unitier{b: str[0]}
	return u.set(str, subtier)
}

func (z zerotier) empty() bool {
	return true
}

type unitier struct {
	b byte
	t tier
}

func (t *unitier) get(b byte) tier {
	if t != nil && t.b == b {
		return t.t
	}
	return nil
}

func (t *unitier) set(str []byte, subtier tier) tier {
	if t == nil {
		u := &unitier{b: str[0]}
		return u.set(str, subtier)
	}
	if t.b == str[0] {
		if len(str) == 1 {
			t.t = subtier
			return t
		}
		if t.t == nil {
			t.t = &unitier{b: str[1]}
		}
		t.t = t.t.set(str[1:], subtier)
		return t
	}
	a := new(arraytier)
	(*a)[t.b] = t.t
	return a.set(str, subtier)
}

func (t *unitier) empty() bool { return false }

type arraytier [256]tier

var emptyArraytier arraytier

func (t *arraytier) get(b byte) tier {
	return t[b]
}

func (t *arraytier) set(str []byte, subtier tier) tier {
	if len(str) == 1 {
		(*t)[str[0]] = subtier
	} else {
		el := (*t)[str[0]]
		if el == nil {
			el = &unitier{b: str[1]}
		}
		(*t)[str[0]] = el.set(str[1:], subtier)
	}
	return t
}

func (t *arraytier) empty() bool {
	return t == nil || *t == emptyArraytier
}
