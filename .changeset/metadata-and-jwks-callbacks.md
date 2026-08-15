---
'@openid4vc/oauth2': patch
'@openid4vc/openid4vci': patch
'@openid4vc/openid4vp': patch
---

Add `getAuthorizationServerMetadata` and `getJwks` callbacks to the `CallbackContext`, allowing authorization server metadata and JWK Sets to be resolved without performing a request.

This makes it possible to avoid network requests for metadata and keys that the caller already has (for example an authorization server hosted by the same application, which would otherwise result in an HTTP request to itself when verifying an access token it issued), and to serve metadata and keys from a cache.

Both callbacks are optional. If not provided, or if they return `undefined`, the metadata and JWK Sets are fetched over HTTP as before. `getAuthorizationServerMetadata` can additionally return `null` to indicate the metadata definitively does not exist, so it is not requested again.

Values returned by the callbacks are validated exactly like fetched values: a JWK Set is parsed with the JWK Set schema, and authorization server metadata is parsed with the authorization server metadata schema and must have an `issuer` matching the requested issuer.

The second parameter of the exported `fetchJwks` and `fetchAuthorizationServerMetadata` functions now also accepts an object with `fetch` and the matching resolve callback, in addition to the `Fetch` implementation it accepted before.
