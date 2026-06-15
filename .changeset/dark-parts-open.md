---
"@openid4vc/openid4vci": patch
---

fix: legacy fallback to extracting authorization server metadata from issuer metadata. This broke with making grant_types_suppoted required. To not introduce a breaking change, we now assume the issuer only supports pre-auth flow if the authorization server metadata is in the issuer metadata. This legacy behavior will be removed once support for pre v1.0 oid4vci draft versions will be removed
