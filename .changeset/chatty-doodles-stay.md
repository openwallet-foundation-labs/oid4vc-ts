---
"@openid4vc/openid4vci": minor
---

feat: stricter type validation for credential_signing_alg_values_supported. Especially for `mso_mdoc` this will have impact as it will disallow the use of string identifiers, since the spec requires it to be COSE Algorithms (numbers)
