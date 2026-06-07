---
"@openid4vc/openid4vp": patch
---

fix: signed openid4vp requests without an `aud` field set now set the `aud` field to 'https://self-issued.me/v2' according to OpenID4VP section 5.8
