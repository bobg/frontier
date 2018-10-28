// Package frontier implements frontier sets, the complement of a set of byte strings.
//
// A Frontier is a trie that contains the shortest bytewise prefixes of all strings _not_ in a set.
// To show in zero knowledge that a given string is not in a Frontier's complement set,
// build a Merkle hash tree from the prefix strings in the Frontier,
// then show via a Merkle proof that some prefix of the given string is in that tree.
//
// How it works:
// Consider the simplified alphabet a,b,c,d,
// a hypothetical set S of strings in that alphabet,
// and the corresponding frontier set F representing everything not in S,
// such that adding a string to S means also excluding it from F.
// When S is empty, so is F, meaning nothing has been excluded.
// F contains the empty prefix: the prefix of all strings.
// Now we add "a" to S.
// This means removing the empty prefix from F and adding the following:
//   b, c, d, aa, ab, ac, ad
// All strings starting with those prefixes are not in S.
// If we next add "abc" to S,
// we must remove "ab" from F and add:
//   aba, abb, abd, abca, abcb, abcc, abcd
//
// See "Zero Knowledge Sets" by Micali, Rabin, Kilian.
//   https://people.csail.mit.edu/silvio/Selected%20Scientific%20Papers/Zero%20Knowledge/Zero-Knowledge_Sets.pdf
package frontier
