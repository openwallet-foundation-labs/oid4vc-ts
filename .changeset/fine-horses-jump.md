---
"@openid4vc/openid4vci": minor
---

All types related to the legacy `vc+sd-jwt` format (now `dc+sd-jwt`) have been renamed and marked as deprecated:

- `SdJwtVcFormatIdentifier` is now `LegacySdJwtVcFormatIdentifier`
- `zSdJwtVcCredentialIssuerMetadataDraft14` is now `zLegacySdJwtVcCredentialIssuerMetadataDraft14`
- `zSdJwtVcCredentialRequestFormatDraft14` is now `zLegacySdJwtVcCredentialRequestFormatDraft14`
- `zSdJwtVcFormatIdentifier` is now `zLegacySdJwtVcFormatIdentifier`

Please update your implementations to use the new `dc+sd-jwt` format.
