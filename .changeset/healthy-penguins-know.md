---
"@openid4vc/openid4vp": patch
---

fix: actually pass `additionalJwtPayload` in openid4vp authorization request. Before in `createOpenid4vpAuthorizationRequest`, if `jar.additionalJwtPayload.aud` was undefined, the `additionalJwtPayload` was never passed the payload from the options.
