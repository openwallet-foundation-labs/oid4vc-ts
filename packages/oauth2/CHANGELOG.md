# @openid4vc/oauth2

## 0.4.1

### Patch Changes

- @openid4vc/utils@0.4.1

## 0.4.0

### Minor Changes

- dfa7819: Remove support for the CommonJS/CJS syntax. Since React Native bundles your code, the update to ESM should not cause issues. In addition all latest minor releases of Node 20+ support requiring ESM modules. This means that even if you project is still a CommonJS project, it can now depend on ESM modules. For this reason oid4vc-ts is now fully an ESM module.

### Patch Changes

- Updated dependencies [dfa7819]
  - @openid4vc/utils@0.4.0

## 0.3.0

### Minor Changes

- 70b9740: Add support for OpenID4VCI draft 15. It also includes improved support for client (wallet) attestations, and better support for server side verification.

  Due to the changes between Draft 14 and Draft 15 and it's up to the caller of this library to handle the difference between the versions. Draft 11 is still supported based on Draft 14 syntax (and thus will be automatically converted).

- fccae5c: chore: update to zod 4. Although the public API has not changed, it does impact the error messages and some of the error structures
- 06c016f: apu and apv in JWE encryptor are now base64 encoded values, to align with JOSE
- 06db16a: feat: add support for JAR in pushed authorization requests.

  NOTE: the `parsePushedAuthorizationRequest` now optionally returns an `authorizationRequestJwt` parameter. You MUST pass this to the `verifyPushedAuthorizationResponse` method to ensure the JWT is verified.

- 70b9740: fix typo in param from authorizationServerMetata to authorizationServerMetadata
- 70b9740: replace the `dpopJwk` return value with `dpop` object with `jwk` key. It now also returns the `jwkThumbprint`
- 26451d7: Before this PR, all packages used Valibot for data validation.
  We have now fully transitioned to Zod. This introduces obvious breaking changes for some packages that re-exported Valibot types or schemas for example.
- f798259: refactor: change the jwt signer method 'trustChain' to 'federation' and make 'trustChain' variable optional.
- c23c86f: add support for sha-384, sha-512, rename SHA-256 to sha-256 to align with IANA hash algorithm names (https://www.iana.org/assignments/named-information/named-information.xhtml)

### Patch Changes

- 08dbc00: Add grant_types_supported to the authorization server metadata.
- a70c87b: fix: make key_ops array of strings instead of string in jwk
- 5b69ca4: Fixes miscellaneous typos and adds code to the authorization request.
- e206509: Add support for deferred credential issuance and Draft 16 of the OpenID for Verifiable Credential Issuance.
- 2cc4e31: Add function to parse authorization response redirect URLs.
- e206509: Fix a myriad of typos across errors, comments, and variable names.
- c29dd5a: fix: entry file in package.json for cjs to point to the correct file extension
- c8ce780: fix: path where oauth2 authorization server metadata is retrieved from.

  For OAuth you need to put `.well-known/oauth-authorization-server` between the origin and path (so `https://funke.animo.id/provider` becomes `https://funke.animo.id/.well-known/oauth-authorization-server/provider`). We were putting the well known path after the full issuer url.

  It will now first check the correct path, and fall back to the invalid path.

- e9483ca: Add support for parsing and verifying an ID Token JWT according to the OpenID Connect specification.

  Exports some other utilities.

- c2c3499: Add authorization server support for refresh tokens, as well as verifying requests with refresh token grants.
- 9bf578f: fix: loosen the allowed content type for JWK Set to include application/json
- 158fa8c: feat: support node 22 and 24
- d9b8118: feat: add `kid` to the JwtSigner interface
- 4d1bfd7: Add function to parse a pushed authorization request uri.
- 3b9b88a: fix: create fetch wrapper that always calls toString on URLSearchParams as React Native does not encode this correctly while Node.JS does
- ef05cf9: Correctly passes the state down to the authentication challenge request.
- 1ba4a59: Add support for parsing and verifying array 'aud' in JWTs.
- 80d0ec1: Send redirect_uri along in the authorization challenge endpoint, allowing the server to use it when defaulting to a PAR request.
- 1ad09cf: Pass state onto the authorization request URL.
- Updated dependencies [70b9740]
- Updated dependencies [fccae5c]
- Updated dependencies [70b9740]
- Updated dependencies [c29dd5a]
- Updated dependencies [26451d7]
- Updated dependencies [158fa8c]
- Updated dependencies [3b9b88a]
  - @openid4vc/utils@0.3.0

## 0.2.0

### Minor Changes

- 0f60387: feat: add client attestations
- 3f6d360: change order of fetching authorization server metadata. First `oauth-authorization-server` metadata is fetched now. If that returns a 404, the `openid-configuration` will be fetched.

### Patch Changes

- @openid4vc/utils@0.2.0

## 0.1.4

### Patch Changes

- 12a517a: feat: add refresh_token grant type
  - @openid4vc/utils@0.1.4

## 0.1.3

### Patch Changes

- d4b9279: chore: create github release
- Updated dependencies [d4b9279]
  - @openid4vc/utils@0.1.3

## 0.1.2

### Patch Changes

- 1de27e5: chore: correct formatting for publishing
- Updated dependencies [1de27e5]
  - @openid4vc/utils@0.1.2

## 0.1.1

### Patch Changes

- 6434781: docs: add readme
- Updated dependencies [6434781]
  - @openid4vc/utils@0.1.1

## 0.1.0

### Minor Changes

- 71326c8: feat: initial release

### Patch Changes

- Updated dependencies [71326c8]
  - @openid4vc/utils@0.1.0
