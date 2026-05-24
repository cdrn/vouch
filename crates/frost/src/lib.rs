// vouch-frost: 2-of-2 FROST (frost-secp256k1-tr) wrapper.
//
// DKG, sign, and refresh ceremonies live here. The crate intentionally
// hides the underlying frost-core generics behind a narrow API tuned for
// the wallet's flow.
