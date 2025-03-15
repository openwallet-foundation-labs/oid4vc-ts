---
"@openid4vc/openid4vci": patch
"@openid4vc/oauth2": patch
---

fix: path where oauth2 authorization server metadata is retrieved from.

For OAuth you need to put `.well-known/oauth-authorization-server` between the origin and path (so `https://funke.animo.id/provider` becomes `https://funke.animo.id/.well-known/oauth-authorization-server/provider`). We were putting the well known path after the full issuer url.

It will now first check the correct path, and fall back to the invalid path.
