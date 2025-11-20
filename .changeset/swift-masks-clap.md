---
"@openid4vc/openid4vci": minor
---

feat: do not break on invalid credential configurations that are not used for the current exchange. A new `knownCredentialConfigurationsSupported` is added to the issuer metadata result, which contain the valid credential configurations for known formats.

Only a shallow validation is done when receiving the metadata, allowing metadata with some invalid configurations for format-specific properties to stil be used for issuing and requesting other credential configurations.
