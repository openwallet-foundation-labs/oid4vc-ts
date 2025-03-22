# @openid4vc/oauth2

## 0.3.0

### Minor Changes

- 26451d7: Before this PR, all packages used Valibot for data validation.
  We have now fully transitioned to Zod. This introduces obvious breaking changes for some packages that re-exported Valibot types or schemas for example.
- c23c86f: add support for sha-384, sha-512, rename SHA-256 to sha-256 to align with IANA hash algorithm names (https://www.iana.org/assignments/named-information/named-information.xhtml)

### Patch Changes

- c8ce780: fix: path where oauth2 authorization server metadata is retrieved from.

  For OAuth you need to put `.well-known/oauth-authorization-server` between the origin and path (so `https://funke.animo.id/provider` becomes `https://funke.animo.id/.well-known/oauth-authorization-server/provider`). We were putting the well known path after the full issuer url.

  It will now first check the correct path, and fall back to the invalid path.

- 3b9b88a: fix: create fetch wrapper that always calls toString on URLSearchParams as React Native does not encode this correctly while Node.JS does
- Updated dependencies [26451d7]
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
