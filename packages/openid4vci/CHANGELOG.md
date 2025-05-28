# @openid4vc/openid4vci

## 0.3.0

### Minor Changes

- 70b9740: Add support for OpenID4VCI draft 15. It also includes improved support for client (wallet) attestations, and better support for server side verification.

  Due to the changes between Draft 14 and Draft 15 and it's up to the caller of this library to handle the difference between the versions. Draft 11 is still supported based on Draft 14 syntax (and thus will be automatically converted).

- 70b9740: fix typo in param from authorizationServerMetata to authorizationServerMetadata
- 1b5e003: renamed oid4vci to openid4vci. This includes the package name, but also the class names and oid4vpRequestUrl to openid4vpRequestUrl
- 70b9740: replace the `dpopJwk` return value with `dpop` object with `jwk` key. It now also returns the `jwkThumbprint`
- 26451d7: Before this PR, all packages used Valibot for data validation.
  We have now fully transitioned to Zod. This introduces obvious breaking changes for some packages that re-exported Valibot types or schemas for example.
- f798259: refactor: change the jwt signer method 'trustChain' to 'federation' and make 'trustChain' variable optional.
- c23c86f: add support for sha-384, sha-512, rename SHA-256 to sha-256 to align with IANA hash algorithm names (https://www.iana.org/assignments/named-information/named-information.xhtml)

### Patch Changes

- ec552d7: support key-attestation+jwt in addition to keyattestation+jwt when verifying key attestation
- c8ce780: fix: path where oauth2 authorization server metadata is retrieved from.

  For OAuth you need to put `.well-known/oauth-authorization-server` between the origin and path (so `https://funke.animo.id/provider` becomes `https://funke.animo.id/.well-known/oauth-authorization-server/provider`). We were putting the well known path after the full issuer url.

  It will now first check the correct path, and fall back to the invalid path.

- 3b9b88a: fix: create fetch wrapper that always calls toString on URLSearchParams as React Native does not encode this correctly while Node.JS does
- Updated dependencies [70b9740]
- Updated dependencies [06c016f]
- Updated dependencies [a70c87b]
- Updated dependencies [70b9740]
- Updated dependencies [70b9740]
- Updated dependencies [c8ce780]
- Updated dependencies [26451d7]
- Updated dependencies [f798259]
- Updated dependencies [d9b8118]
- Updated dependencies [c23c86f]
- Updated dependencies [3b9b88a]
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
