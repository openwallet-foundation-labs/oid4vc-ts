---
"@openid4vc/oauth2": patch
---

Add support for the DPoP-bound `attest_jwt_client_auth_dpop` client authentication method (draft 09 §5.2): a new `clientAuthenticationClientAttestationJwtDpop` client-auth callback that emits a single DPoP proof doubling as the Client Attestation PoP (client instance key == DPoP key), plus authorization-server verification of the combined method (attestation JWT + DPoP proof with a mandatory `cnf` JWK to DPoP key match). The combined method is rejected when the authorization server advertises client authentication methods that do not include `attest_jwt_client_auth_dpop`.
