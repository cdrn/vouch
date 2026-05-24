# vouch

passport-recoverable 2/2 FROST schnorr wallet on Base.

a signing scheme where account recovery uses a zero-knowledge proof of
passport ownership against an opaque commitment — the recovery
provider learns nothing about the user's identity beyond "the same
human who set this account up is back."

design: [SPEC.md](SPEC.md)

## status

pre-alpha. nothing here works yet. not audited. not deployed. do not
put money in this.

## layout

| path | what |
| --- | --- |
| `crates/frost` | FROST DKG / sign / refresh wrapper (`vouch-frost`) |
| `crates/signer` | signing service — one ceremony participant exposed as a service (`vouch-signer`) |
| `crates/relay` | websocket message bus for ceremonies (`vouch-relay`) |
| `contracts/` | solidity: schnorr verifier + 4337 account contract |
| `client/` | wallet client (stack TBD) |
| `docs/` | design notes |

the signer is built as a single ceremony participant rather than a
"co-signer backend." v0 runs one instance; the protocol surface
doesn't bake in the assumption that there will only ever be one.

## license

Apache-2.0. see [LICENSE](LICENSE).
