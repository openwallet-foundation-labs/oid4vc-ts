---
"@openid4vc/openid4vci": minor
"@openid4vc/oauth2": minor
"@openid4vc/utils": minor
---

Add support for OpenID4VCI draft 15. It also includes improved support for client (wallet) attestations, and better support for server side verification.

Due to the changes between Draft 14 and Draft 15 and it's up to the caller of this library to handle the difference between the versions. Draft 11 is still supported based on Draft 14 syntax (and thus will be automatically converted).
