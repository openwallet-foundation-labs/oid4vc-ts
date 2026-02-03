# @openid4vc/openid4vp

## 0.4.5

### Patch Changes

- Updated dependencies [9c0ac58]
- Updated dependencies [4fb7574]
  - @openid4vc/oauth2@0.4.5
  - @openid4vc/utils@0.4.5

## 0.4.4

### Patch Changes

- 3f3cfe7: chore: better zod errors with more detail of nested errors
- Updated dependencies [0bf46b7]
- Updated dependencies [3f3cfe7]
- Updated dependencies [3f3cfe7]
  - @openid4vc/oauth2@0.4.4
  - @openid4vc/utils@0.4.4

## 0.4.3

### Patch Changes

- @openid4vc/oauth2@0.4.3
- @openid4vc/utils@0.4.3

## 0.4.2

### Patch Changes

- f07e928: fix: actually pass `additionalJwtPayload` in openid4vp authorization request. Before in `createOpenid4vpAuthorizationRequest`, if `jar.additionalJwtPayload.aud` was undefined, the `additionalJwtPayload` was never passed the payload from the options.
- Updated dependencies [05af867]
  - @openid4vc/utils@0.4.2
  - @openid4vc/oauth2@0.4.2

## 0.4.1

### Patch Changes

- @openid4vc/oauth2@0.4.1
- @openid4vc/utils@0.4.1

## 0.4.0

### Minor Changes

- dfa7819: Remove support for the CommonJS/CJS syntax. Since React Native bundles your code, the update to ESM should not cause issues. In addition all latest minor releases of Node 20+ support requiring ESM modules. This means that even if you project is still a CommonJS project, it can now depend on ESM modules. For this reason oid4vc-ts is now fully an ESM module.

### Patch Changes

- Updated dependencies [dfa7819]
  - @openid4vc/oauth2@0.4.0
  - @openid4vc/utils@0.4.0

## 0.3.0

### Minor Changes

- edd7464: update the parsed dcql vp_token presentation result to always return an array of presentations
- 7904088: feat: support multi-presentation submission for transaction data (dcql multiple feature)
- 16e5b1c: feat: add support for `x509_hash` client id scheme.

  With support for this new client id scheme the `hash` callback is now required in the `Openid4vpClient`, and the `validateOpenid4vpClientId` method is now asynchronous.

- 1b5e003: feat: initial version of openid4vp
- fccae5c: chore: update to zod 4. Although the public API has not changed, it does impact the error messages and some of the error structures
- 06c016f: apu and apv in JWE encryptor are now base64 encoded values, to align with JOSE
- 06db16a: feat: add support for JAR in pushed authorization requests.

  NOTE: the `parsePushedAuthorizationRequest` now optionally returns an `authorizationRequestJwt` parameter. You MUST pass this to the `verifyPushedAuthorizationResponse` method to ensure the JWT is verified.

- 16e5b1c: refactor: client id scheme to client id prefix.

  All parameters have been changed to use prefix, so .e.g. `scheme` has become `prefix`. Only the parameters referring to the legacy separate `client_id_scheme` are still called scheme.

- 16e5b1c: feat: support the new `origin:` client id prefix in addition to `web-origin:` for the DC API.

  NOTE that for unsigned requests over the DC API, the `client_id` should be omitted, and you need to calculate the effective client id. Up to draft 25 this was `web-origin:<origin>` and after draft 25 it's `origin:<origin>`. It's not always possible to detect which prefix needs to be used, so if you're a verifier that wants to support both draft versions with the DC API, make sure to allow both prefixes for the session binding of presentations.

- 16e5b1c: add support for response encryption without leveraging JARM.

  Both the JARM-based response encryption, and the new OID4VP-based response encryption methods are supported. Both methods are used to determine which alg and enc values to use, and you should provide the same `jarm` configuration options. Once support for pre-1.0 drafts will be removed, the JARM options will also be replaced with a more OID4VP aligned API.

- 16e5b1c: feat: add support for draft 27 vp_formats_supported
- f798259: refactor: change the jwt signer method 'trustChain' to 'federation' and make 'trustChain' variable optional.
- 16e5b1c: feat: add support for the new `decentralized_identifier` and `openid_federation` client id schemes.

  The client information is also updated to return the `decentralized_identifier` and `openid_federation` scheme. The `effective` client is the value that should be used for comparison.

- edd7464: feat: update openid4vp to 1.0 final.

  The `version` returned in the `resolveOpenid4vpAuthorizationRequest` now returns `100` instead of `29` for the 1.0 final version of OpenID4VP.

### Patch Changes

- 0d8a658: Added `verifier_attestations` to DC Api type
- 8ca38b5: Fixes the response_uri check against the client identifier.
- 16e5b1c: feat: support verifier_attestation in addition to verifier_info
- 0fffe73: feat: return decryption jwk in verified jarm response
- 16e5b1c: feat: correctly extract jwk from jarm kid if defined
- c29dd5a: fix: entry file in package.json for cjs to point to the correct file extension
- 16e5b1c: deprecate the `x509_san_uri` client id scheme for draft 25+
- 919ef7c: fix: check whether client id identifier matches redirect_uri/resposne_uri when client id prefix is redirect_uri
- 16e5b1c: feat: add support for client_id_prefixes in addition to client_id_schemes
- 04db7c2: fix: set the effective client id to start with `web-origin:` for pre draft 25 authorization requests
- 4fd875d: Retain the `.passthrough()` in the Zod common credential configuration's for correct typing.
- 5abf3aa: feat: add method to calculate x509_hash
- 1e6b8c4: Fixes the parsing of the deferred credential response.
- 1a64f80: fix: allow string for expires_in when parsing openid4vp response payload to account for response submitted as url encoded
- 2e0249b: Exposed types and schema for verifier attestations
- 971f885: fix: export JarmMode enum
- 16e5b1c: feat: add `version` to the `resolveOpenid4vpAuthorizationRequest` return value, indicating the highest supported draft version for the authorization request
- 1c57f07: feat: allow providing custom JARM encryption jwk
- e1bd4e8: - Added `verifier_attestations` parsing
- 158fa8c: feat: support node 22 and 24
- 3b9b88a: fix: create fetch wrapper that always calls toString on URLSearchParams as React Native does not encode this correctly while Node.JS does
- 1ba4a59: Add support for parsing and verifying array 'aud' in JWTs.
- Updated dependencies [70b9740]
- Updated dependencies [fccae5c]
- Updated dependencies [06c016f]
- Updated dependencies [06db16a]
- Updated dependencies [08dbc00]
- Updated dependencies [a70c87b]
- Updated dependencies [5b69ca4]
- Updated dependencies [e206509]
- Updated dependencies [2cc4e31]
- Updated dependencies [e206509]
- Updated dependencies [70b9740]
- Updated dependencies [c29dd5a]
- Updated dependencies [70b9740]
- Updated dependencies [c8ce780]
- Updated dependencies [26451d7]
- Updated dependencies [e9483ca]
- Updated dependencies [c2c3499]
- Updated dependencies [f798259]
- Updated dependencies [9bf578f]
- Updated dependencies [158fa8c]
- Updated dependencies [d9b8118]
- Updated dependencies [c23c86f]
- Updated dependencies [4d1bfd7]
- Updated dependencies [3b9b88a]
- Updated dependencies [ef05cf9]
- Updated dependencies [1ba4a59]
- Updated dependencies [80d0ec1]
- Updated dependencies [1ad09cf]
  - @openid4vc/oauth2@0.3.0
  - @openid4vc/utils@0.3.0
