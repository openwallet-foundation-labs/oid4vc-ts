---
"@openid4vc/openid4vp": patch
"@openid4vc/oauth2": patch
"@openid4vc/utils": patch
"@openid4vc/openid4vci": patch
---

fix: create fetch wrapper that always calls toString on URLSearchParams as React Native does not encode this correctly while Node.JS does
