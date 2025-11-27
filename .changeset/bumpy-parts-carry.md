---
"@openid4vc/openid4vci": minor
"@openid4vc/openid4vp": minor
"@openid4vc/oauth2": minor
"@openid4vc/utils": minor
---

Remove support for the CommonJS/CJS syntax. Since React Native bundles your code, the update to ESM should not cause issues. In addition all latest minor releases of Node 20+ support requiring ESM modules. This means that even if you project is still a CommonJS project, it can now depend on ESM modules. For this reason oid4vc-ts is now fully an ESM module. 