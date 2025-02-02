---
"@openid4vc/oid4vci": minor
"@openid4vc/oauth2": minor
"@openid4vc/utils": minor
---

Before this PR, all packages used Valibot for data validation.  
We have now fully transitioned to Zod. This introduces obvious breaking changes for some packages that re-exported Valibot types or schemas for example.
