---
"@openid4vc/oauth2": minor
---

Add configurable DPoP proof freshness and replay validation hooks.

- Add optional `maxProofAgeSeconds` and `allowedClockSkewSeconds` checks in DPoP verification.
- Add optional `assertJtiUniqueness` callback for replay protection.
- Thread these DPoP verification options through access-token, authorization-request, and resource-request verification APIs.
- Add tests for DPoP validation edge cases and `use_dpop_nonce` retry behavior with fresh proofs.
