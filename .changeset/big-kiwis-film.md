---
"@openid4vc/openid4vp": minor
---

feat: add support for `x509_hash` client id scheme.

With support for this new client id scheme the `hash` callback is now required in the `Openid4vpClient`, and the `validateOpenid4vpClientId` method is now asynchronous.
