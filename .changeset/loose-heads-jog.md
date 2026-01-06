---
"@openid4vc/openid4vci": patch
"@openid4vc/oauth2": patch
---

feat: add support for RFC 9207 OAuth 2.0 Authorization Server Issuer Identification and add methods to the Oauth2Client and Openid4vciClient to parse and verify an authorization response. To meet HAIP requirements you should set `authorization_response_iss_parameter_supported` to true in your authorization server, and in the wallet you should use the new `Openid4vciClient.parseAndVerifyAuthorizationResponseRedirectUrl` to parse and verify the authorization response. The verification method only verifies against the authorization server metadata, while HAIP/FAPI require the value to ALWAYS be present. In the future a method will be added that verifies if the authorization server metadata is aligned with the requirements of HAIP. This way the verification methods can stay simpler, and verify based on the authorization server metadata.
