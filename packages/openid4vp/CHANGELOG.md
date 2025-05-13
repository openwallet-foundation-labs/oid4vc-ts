# @openid4vc/openid4vp

## 0.3.0

### Minor Changes

- 1b5e003: feat: initial version of openid4vp
- 06c016f: apu and apv in JWE encryptor are now base64 encoded values, to align with JOSE
- f798259: refactor: change the jwt signer method 'trustChain' to 'federation' and make 'trustChain' variable optional.

### Patch Changes

- 971f885: fix: export JarmMode enum
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
