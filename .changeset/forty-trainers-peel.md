---
"@openid4vc/openid4vci": patch
"@openid4vc/utils": patch
---

fix: add fallback handling when fetch request fails for metadata requests which have multiple URLs to be tried. It's impossible to e.g. detect a CORS exception,
so instead we try the other URLs in case of a fetch error, and only throw the error if all requests failed. 

This is supported for both fetching credential issuer metadata and authorization server metadata.
