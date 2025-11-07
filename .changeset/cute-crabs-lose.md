---
"@openid4vc/openid4vci": minor
"@openid4vc/openid4vp": minor
"@openid4vc/oauth2": minor
---

feat: add support for JAR in pushed authorization requests.

NOTE: the `parsePushedAuthorizationRequest` now optionally returns an `authorizationRequestJwt` parameter. You MUST pass this to the `verifyPushedAuthorizationResponse` method to ensure the JWT is verified.
