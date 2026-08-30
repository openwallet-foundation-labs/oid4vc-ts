---
'@openid4vc/openid4vp': patch
---

Ignore the pre-draft-27 `authorization_encrypted_response_alg` and `authorization_encrypted_response_enc` client metadata parameters when the verifier also sends the 1.0 `encrypted_response_enc_values_supported`. Previously a verifier sending both generations of the response encryption metadata could fail with `Invalid authorization_encryption_enc`.
