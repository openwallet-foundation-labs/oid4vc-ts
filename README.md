<p align="center">
  <picture>
   <source media="(prefers-color-scheme: light)" srcset="https://res.cloudinary.com/animo-solutions/image/upload/v1656578320/animo-logo-light-no-text_ok9auy.svg">
   <source media="(prefers-color-scheme: dark)" srcset="https://res.cloudinary.com/animo-solutions/image/upload/v1656578320/animo-logo-dark-no-text_fqqdq9.svg">
   <img alt="Animo Logo" height="250px" />
  </picture>
</p>

<h1 align="center" ><b>OpenID for Verifiable Credentials - TypeScript</b></h1>

<h4 align="center">Powered by &nbsp; 
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="https://res.cloudinary.com/animo-solutions/image/upload/v1656579715/animo-logo-light-text_cma2yo.svg">
    <source media="(prefers-color-scheme: dark)" srcset="https://res.cloudinary.com/animo-solutions/image/upload/v1656579715/animo-logo-dark-text_uccvqa.svg">
    <img alt="Animo Logo" height="12px" />
  </picture>
</h4><br>

<p align="center">
  <a href="https://typescriptlang.org">
    <img src="https://img.shields.io/badge/%3C%2F%3E-TypeScript-%230074c1.svg" />
  </a>
</p>

<p align="center">
  <a href="#packages">Packages</a> 
  &nbsp;|&nbsp;
  <a href="#getting-started">Getting started</a> 
  &nbsp;|&nbsp;
  <a href="#usage">Usage</a> 
  &nbsp;|&nbsp;
  <a href="#contributing">Contributing</a> 
  &nbsp;|&nbsp;
  <a href="#contributing">License</a> 
</p>

---

## Libraries

### OAuth 2.0 - [`@animo-id/oauth2`](./packages/oauth2)

[![@animo-id/oauth2 version](https://img.shields.io/npm/v/@animo-id/oauth2)](https://npmjs.com/package/@animo-id/oauth2)

An implementation of the [OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749), including extension specifications.

- [RFC 9126 - OAuth 2.0 Pushed Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9126)
- [OAuth 2.0 for First-Party Applications](https://www.ietf.org/archive/id/draft-parecki-oauth-first-party-apps-00.html)
- [RFC 7636 - Proof Key for Code Exchange by OAuth Public Clients](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 9449 - OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
- [RFC 7662 - OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
- [RFC 9068 JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens](https://datatracker.ietf.org/doc/html/rfc9068)

```ts
import {
  ResourceServer,
  AuthorizationServer,
  Oauht2Client,
} from "@animo-id/oauth2";
```

### OpenID for Verifiable Credential Issuance - [`@animo-id/oid4vc`](./packages/oid4vci)

[![@animo-id/oid4vci version](https://img.shields.io/npm/v/@animo-id/oid4vci)](https://npmjs.com/package/@animo-id/oid4vci)

An implementation of the [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) specification.

- Authorization Code Flow and Pre-Authorized Code Flow
- Credential format profiles `vc+sd-jwt`, `mso_mdoc`, `jwt_vc_json`, `jwt_vc_json-ld`, and `ldp_vc` (only object validation, no credential implementation)
- Proof type `jwt`
- Draft 14, with backwards compatibility for draft 13 (ID1), and draft 11
- Support presentation during issuance using Authorization Challenge and OpenID4VP.

```ts
import {
  Oid4vciIssuer
  Oid4vciClient,
} from "@animo-id/oid4vci";
```

## Environments

This library is platform agnostic and support Node.JS, React Native and browsers out of the box, as long as it provides an implementation of `URL` and `URLSearchParams`. However because of this it is required to provide some callbacks for simple things like hashing, generate random bytes, etc. If no global `fetch` is available in your environment, this also need to be provided in the callbacks.

## Contributing

Is there something you'd like to fix or add? Great, we love community
contributions! To get involved, please follow our [contribution guidelines](./CONTRIBUTING.md).

## License

This project is licensed under the Apache License Version 2.0 (Apache-2.0).
