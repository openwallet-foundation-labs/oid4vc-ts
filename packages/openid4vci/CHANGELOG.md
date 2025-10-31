# @openid4vc/openid4vci

## 0.3.0

### Minor Changes

- 70b9740: Add support for OpenID4VCI draft 15. It also includes improved support for client (wallet) attestations, and better support for server side verification.

  Due to the changes between Draft 14 and Draft 15 and it's up to the caller of this library to handle the difference between the versions. Draft 11 is still supported based on Draft 14 syntax (and thus will be automatically converted).

- fccae5c: chore: update to zod 4. Although the public API has not changed, it does impact the error messages and some of the error structures
- 5d46285: Add support for W3C VCDM 2.0 SD-JWT format.
- 5d46285: All types related to the legacy `vc+sd-jwt` format (now `dc+sd-jwt`) have been renamed and marked as deprecated:

  - `SdJwtVcFormatIdentifier` is now `LegacySdJwtVcFormatIdentifier`
  - `zSdJwtVcCredentialIssuerMetadataDraft14` is now `zLegacySdJwtVcCredentialIssuerMetadataDraft14`
  - `zSdJwtVcCredentialRequestFormatDraft14` is now `zLegacySdJwtVcCredentialRequestFormatDraft14`
  - `zSdJwtVcFormatIdentifier` is now `zLegacySdJwtVcFormatIdentifier`

  Please update your implementations to use the new `dc+sd-jwt` format.

- e206509: Add support for deferred credential issuance and Draft 16 of the OpenID for Verifiable Credential Issuance.
- 8c5a70e: feat: update draft 16 to v1.0. This only introduces one breaking change requiring a transaction_id in the deferred credential response. For this reason we replaced the Draft16 support with V1. All other drafts are still supported.
- 70b9740: fix typo in param from authorizationServerMetata to authorizationServerMetadata
- 1b5e003: renamed oid4vci to openid4vci. This includes the package name, but also the class names and oid4vpRequestUrl to openid4vpRequestUrl
- 70b9740: replace the `dpopJwk` return value with `dpop` object with `jwk` key. It now also returns the `jwkThumbprint`
- 53c44bb: Fixes the credential issuer metadata, which is now correctly transformed to the syntax of Draft 16. In addition, some typing issues have also been fixed which prevented to get the types of nested fields.

  In addition, credential type-specific issuer metadata Zod types (e.g., `zMsoMdocCredentialIssuerMetadata`) now also match against the common credential configuration parameters.

- 26451d7: Before this PR, all packages used Valibot for data validation.
  We have now fully transitioned to Zod. This introduces obvious breaking changes for some packages that re-exported Valibot types or schemas for example.
- f798259: refactor: change the jwt signer method 'trustChain' to 'federation' and make 'trustChain' variable optional.
- eaad24f: feat(openid4vci): supported for creating, resolving and verifiying signed credential issuer metadata
- c23c86f: add support for sha-384, sha-512, rename SHA-256 to sha-256 to align with IANA hash algorithm names (https://www.iana.org/assignments/named-information/named-information.xhtml)

### Patch Changes

- 27a508c: feat(openid4vc): support the new issuer metadata url
- 5b69ca4: Fixes miscellaneous typos and adds code to the authorization request.
- e206509: Fix a myriad of typos across errors, comments, and variable names.
- ec552d7: support key-attestation+jwt in addition to keyattestation+jwt when verifying key attestation
- c8ce780: fix: path where oauth2 authorization server metadata is retrieved from.

  For OAuth you need to put `.well-known/oauth-authorization-server` between the origin and path (so `https://funke.animo.id/provider` becomes `https://funke.animo.id/.well-known/oauth-authorization-server/provider`). We were putting the well known path after the full issuer url.

  It will now first check the correct path, and fall back to the invalid path.

- 404e1fe: Fixed the definition of the claims field in the issuer metadata for multiple draft versions.
- 158fa8c: feat: support node 22 and 24
- a28ceaa: The field `credentials` on the types `CredentialResponse` and `DeferredCredentialResponse` has been updated to correctly reflect the object structure present from Draft 15 and onwards of the OpenID for Verifiable Credential Issuance specification.
- 3b9b88a: fix: create fetch wrapper that always calls toString on URLSearchParams as React Native does not encode this correctly while Node.JS does
- 1ba4a59: Add support for parsing and verifying array 'aud' in JWTs.
- Updated dependencies [70b9740]
- Updated dependencies [fccae5c]
- Updated dependencies [06c016f]
- Updated dependencies [08dbc00]
- Updated dependencies [a70c87b]
- Updated dependencies [5b69ca4]
- Updated dependencies [e206509]
- Updated dependencies [2cc4e31]
- Updated dependencies [e206509]
- Updated dependencies [70b9740]
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

## 0.2.0

### Minor Changes

- 0f60387: feat: add key attestations

### Patch Changes

- Updated dependencies [0f60387]
- Updated dependencies [3f6d360]
  - @openid4vc/oauth2@0.2.0
  - @openid4vc/utils@0.2.0

## 0.1.4

### Patch Changes

- Updated dependencies [12a517a]
  - @openid4vc/oauth2@0.1.4
  - @openid4vc/utils@0.1.4

## 0.1.3

### Patch Changes

- d4b9279: chore: create github release
- Updated dependencies [d4b9279]
  - @openid4vc/oauth2@0.1.3
  - @openid4vc/utils@0.1.3

## 0.1.2

### Patch Changes

- 1de27e5: chore: correct formatting for publishing
- Updated dependencies [1de27e5]
  - @openid4vc/oauth2@0.1.2
  - @openid4vc/utils@0.1.2

## 0.1.1

### Patch Changes

- 6434781: docs: add readme
- Updated dependencies [6434781]
  - @openid4vc/oauth2@0.1.1
  - @openid4vc/utils@0.1.1

## 0.1.0

### Minor Changes

- 71326c8: feat: initial release

### Patch Changes

- 3bcbd08: export additional types
- Updated dependencies [71326c8]
  - @openid4vc/oauth2@0.1.0
  - @openid4vc/utils@0.1.0
