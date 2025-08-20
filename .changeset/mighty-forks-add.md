---
"@openid4vc/openid4vci": minor
---

Fixes the credential issuer metadata, which is now correctly transformed to the syntax of Draft 16. In addition, some typing issues have also been fixed which prevented to get the types of nested fields.

In addition, credential type-specific issuer metadata Zod types (e.g., `zMsoMdocCredentialIssuerMetadata`) now also match against the common credential configuration parameters.
