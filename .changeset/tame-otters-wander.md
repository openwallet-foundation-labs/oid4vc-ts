---
"@openid4vc/openid4vci": patch
---

fix: source credential response encryption `alg` from the JWK

`credential_response_encryption` no longer requires a top-level `alg` (per OpenID4VCI V1 the key management algorithm is carried in `jwk.alg`), so parsing no longer fails when it is absent. The optional `zip` parameter was added. The response encryptor now sources `alg` from `jwk.alg`, falling back to a top-level `alg` for backwards compatibility with draft 14/15 wallets (where it was a required member).
