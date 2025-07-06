---
"@openid4vc/openid4vp": minor
---

refactor: client id scheme to client id prefix.

All parameters have been changed to use prefix, so .e.g. `scheme` has become `prefix`. Only the parameters referring to the legacy separate `client_id_scheme` are still called scheme.
