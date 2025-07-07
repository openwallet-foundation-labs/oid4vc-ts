---
"@openid4vc/openid4vp": minor
---

feat: support the new `origin:` client id prefix in addition to `web-origin:` for the DC API.

NOTE that for unsigned requests over the DC API, the `client_id` should be omitted, and you need to calculate the effective client id. Up to draft 25 this was `web-origin:<origin>` and after draft 25 it's `origin:<origin>`. It's not always possible to detect which prefix needs to be used, so if you're a verifier that wants to support both draft versions with the DC API, make sure to allow both prefixes for the session binding of presentations.
