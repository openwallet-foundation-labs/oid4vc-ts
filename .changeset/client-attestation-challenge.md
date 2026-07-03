---
"@openid4vc/oauth2": patch
---

Add `Oauth2Client.requestClientAttestationChallenge` to fetch a Client Attestation challenge from the authorization server's `challenge_endpoint`, and support the `use_attestation_challenge` reactive challenge retry (draft 09) so the challenge is automatically included in the Client Attestation PoP when the server requests one.
