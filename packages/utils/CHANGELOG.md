# @openid4vc/utils

## 0.3.0

### Minor Changes

- 26451d7: Before this PR, all packages used Valibot for data validation.
  We have now fully transitioned to Zod. This introduces obvious breaking changes for some packages that re-exported Valibot types or schemas for example.

### Patch Changes

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
