---
"@openid4vc/openid4vci": patch
---

Bring key attestations in line with the OpenID4VCI 1.0/1.1 key attestation format.

- Emit `key-attestation+jwt` as the `typ` when creating a key attestation (previously the pre-final `keyattestation+jwt`). Verification still accepts the legacy value.
- Fix an inverted validation that rejected a JWT header carrying both `trust_chain` and `kid`; the spec requires `kid` to be present when `trust_chain` is used for signature verification (fixed for both the key attestation and the `jwt` proof type headers).
- Require `attested_keys` (and, when present, `key_storage`/`user_authentication`) to be non-empty arrays.
- Make the `nonce` claim optional at the schema level; it is only required when the Credential Issuer has a Nonce Endpoint, which is enforced via `expectedNonce` during verification.
