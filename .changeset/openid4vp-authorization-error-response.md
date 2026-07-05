---
"@openid4vc/openid4vp": patch
---

Support parsing OpenID4VP Authorization Error Responses. When the wallet returns an authorization error response (e.g. it detected an error with the request, or is unavailable) instead of a successful response containing a `vp_token`, `parseOpenid4VpAuthorizationResponsePayload` (and `parseOpenid4vpAuthorizationResponse`) now throws an `Openid4vpAuthorizationResponseError` with the parsed `errorResponse`, instead of a confusing zod error about the missing `vp_token`.
