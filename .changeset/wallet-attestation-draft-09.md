---
"@openid4vc/oauth2": patch
---

Align wallet (client) attestation with draft 09 of OAuth 2.0 Attestation-Based Client Authentication.

- Client Attestation and Client Attestation PoP JWTs no longer emit the `iss` claim (removed in draft 08). Verification still accepts legacy JWTs that include `iss`.
- The Client Attestation PoP JWT uses the `challenge` claim (renamed from `nonce` in draft 06) and no longer includes `exp` (removed in draft 06). Verification accepts either `challenge` or the legacy `nonce`. The `nonce`/`expectedNonce` options are deprecated aliases for `challenge`/`expectedChallenge`.
- Added authorization server metadata parameters `client_attestation_signing_alg_values_supported` and `client_attestation_pop_signing_alg_values_supported` (draft 07), the `challenge_endpoint` parameter, the `attest_jwt_client_auth_dpop` authentication method, and the `OAuth-Client-Attestation-Challenge` header (draft 09).
- `verifyClientAttestationPopJwt` accepts an `expectedAudience` option so a resource server can verify a PoP JWT bound to its own identifier (draft 09).
