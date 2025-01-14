---
"@openid4vc/oauth2": minor
---

change order of fetching authorization server metadata. First `oauth-authorization-server` metadata is fetched now. If that returns a 404, the `openid-configuration` will be fetched.
