---
"@openid4vc/openid4vci": patch
---

fix(openid4vci): loosen type validation for `format` in credential request. Previously an error would be thrown if both `format` and `credential_configuration_id` were present. Some wallets use this to broaden compatibilty, so it makes sense to not throw on this
