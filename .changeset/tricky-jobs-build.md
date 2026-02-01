---
"@openid4vc/openid4vp": minor
---

it is now required to pass the `responseMode` object to the `resolveOpenid4vpAuthorizationRequest` method. The `responseMode` should contain a type indicating the expected response mode group (`direct_post`, `iae` or `dc_api`) along with response-mode specific parameters (e.g. `expectedOrigin`). This replaces the top-level `origin` parameter, and ensures only expected response modes are used within a context (since you are aware when calling the method whether you're in a DC/IAE or normal context).
