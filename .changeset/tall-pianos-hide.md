---
"@openid4vc/oauth2": patch
"@openid4vc/openid4vci": patch
"@openid4vc/openid4vp": patch
---

Remove exp field from wallet attestation JWT payload schema
Export CreateCredentialResponseOptions type
Pass allowedSkewInSeconds to verifyClientAttestation and verifyAttestationJWT functions, and deprecate clockSkewSec in favor of allowedSkewInSeconds for better naming consistency.
