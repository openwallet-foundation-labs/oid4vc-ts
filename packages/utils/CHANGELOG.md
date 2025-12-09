# @openid4vc/utils

## 0.4.2

### Patch Changes

- 05af867: fix: add fallback handling when fetch request fails for metadata requests which have multiple URLs to be tried. It's impossible to e.g. detect a CORS exception,
  so instead we try the other URLs in case of a fetch error, and only throw the error if all requests failed.

  This is supported for both fetching credential issuer metadata and authorization server metadata.

## 0.4.1

## 0.4.0

### Minor Changes

- dfa7819: Remove support for the CommonJS/CJS syntax. Since React Native bundles your code, the update to ESM should not cause issues. In addition all latest minor releases of Node 20+ support requiring ESM modules. This means that even if you project is still a CommonJS project, it can now depend on ESM modules. For this reason oid4vc-ts is now fully an ESM module.

## 0.3.0

### Minor Changes

- 70b9740: Add support for OpenID4VCI draft 15. It also includes improved support for client (wallet) attestations, and better support for server side verification.

  Due to the changes between Draft 14 and Draft 15 and it's up to the caller of this library to handle the difference between the versions. Draft 11 is still supported based on Draft 14 syntax (and thus will be automatically converted).

- fccae5c: chore: update to zod 4. Although the public API has not changed, it does impact the error messages and some of the error structures
- 70b9740: fix typo in param from authorizationServerMetata to authorizationServerMetadata
- 26451d7: Before this PR, all packages used Valibot for data validation.
  We have now fully transitioned to Zod. This introduces obvious breaking changes for some packages that re-exported Valibot types or schemas for example.

### Patch Changes

- c29dd5a: fix: entry file in package.json for cjs to point to the correct file extension
- 158fa8c: feat: support node 22 and 24
- 3b9b88a: fix: create fetch wrapper that always calls toString on URLSearchParams as React Native does not encode this correctly while Node.JS does

## 0.2.0

## 0.1.4

## 0.1.3

### Patch Changes

- d4b9279: chore: create github release

## 0.1.2

### Patch Changes

- 1de27e5: chore: correct formatting for publishing

## 0.1.1

### Patch Changes

- 6434781: docs: add readme

## 0.1.0

### Minor Changes

- 71326c8: feat: initial release
