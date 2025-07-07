---
"@openid4vc/openid4vp": minor
---

add support for the response encryption without levearging JARM.

Both the JARM-based response encryption, and the new OID4VP-based response encryption methods are supported. Both methods are used to determine which alg and enc values to use, and you should provide the same `jarm` configuration options. Once support for pre-1.0 drafts will be removed, the JARM will also be replaced with a more OID4VP aligned API.
