<h1 align="center" ><b>OpenID for Verifiable Credentials - TypeScript</b></h1>

<p align="center">
  <a href="https://typescriptlang.org">
    <img src="https://img.shields.io/badge/%3C%2F%3E-TypeScript-%230074c1.svg" />
  </a>
</p>

<p align="center">
  <a href="#oauth-20---openid4vcoauth2">OAuth 2.0</a> 
  &nbsp;|&nbsp;
  <a href="#openid-for-verifiable-credential-issuance---openid4vcopenid4vci">OpenID for Verifiable Credential Issuance</a> 
  &nbsp;|&nbsp;
  <a href="#openid-for-verifiable-preentations---openid4vcopenid4vp">OpenID for Verifiable Presentations</a> 
  &nbsp;|&nbsp;
  <a href="#supported-environments">Supported Environments</a>
  &nbsp;|&nbsp;
  <a href="#contributing">Contributing</a>
  &nbsp;|&nbsp;
  <a href="#license">License</a>
  &nbsp;|&nbsp;
  <a href="#license">Credits</a>
</p>

---

## OAuth 2.0 - [`@openid4vc/oauth2`](./packages/oauth2)

[![@openid4vc/oauth2 version](https://img.shields.io/npm/v/@openid4vc/oauth2)](https://npmjs.com/package/@openid4vc/oauth2)

An implementation of the [OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749), including extension specifications.

- [RFC 9126 - OAuth 2.0 Pushed Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9126)
- [OAuth 2.0 for First-Party Applications - Draft 0](https://www.ietf.org/archive/id/draft-ietf-oauth-first-party-apps-00.html)
- [RFC 7636 - Proof Key for Code Exchange by OAuth Public Clients](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 9449 - OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
- [RFC 7662 - OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
- [RFC 9068 JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens](https://datatracker.ietf.org/doc/html/rfc9068)
- [RFC 8707 - Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/rfc/rfc8707.html)

```ts
import {
  ResourceServer,
  AuthorizationServer,
  Oauth2Client,
} from "@openid4vc/oauth2";
```

## OpenID for Verifiable Credential Issuance - [`@openid4vc/openid4vci`](./packages/openid4vci)

[![@openid4vc/openid4vci version](https://img.shields.io/npm/v/@openid4vc/openid4vci)](https://npmjs.com/package/@openid4vc/openid4vci)

An implementation of the [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) specification.

- Authorization Code Flow and Pre-Authorized Code Flow
- Credential format profiles `vc+sd-jwt`, `dc+sd-jwt`, `mso_mdoc`, `jwt_vc_json`, `jwt_vc_json-ld`, and `ldp_vc` (only object validation, no credential implementation)
- Proof type `jwt`
- Draft 16, with backwards compatibility for draft 14, draft 13 (ID1), and draft 11
- Support presentation during issuance using Authorization Challenge and OpenID4VP.

```ts
import {
  Openid4vciIssuer
  Openid4vciClient,
} from "@openid4vc/openid4vci";
```

## OpenID for Verifiable Presentations - [`@openid4vc/openid4vp`](./packages/openid4vp)

[![@openid4vc/openid4vp version](https://img.shields.io/npm/v/@openid4vc/openid4vp)](https://npmjs.com/package/@openid4vc/openid4vp)

An implementation of the [OpenID for Verifiable Presentations](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) specification.

- Signed and unsigned requests
- Support for response mode `direct_post`, `direct_post.jwt`, `dc_api` and `dc_api.jwt`
- No out of the box support for Presentation Exchange or DCQL, this needs to be provided using e.g. [dcql-ts](https://github.com/openwallet-foundation-labs/dcql-ts) or [PEX](https://github.com/Sphereon-Opensource/PEX).
- Transaction Data
- Supports OpenID4VP Draft 18 to 24
- Support for JWT Secured Authorization Request (JAR)
- Support for JWT Secure Authorization Response Mode (JARM)

```ts
import {
  Openid4vpVerifier
  Openid4vpClient,
} from "@openid4vc/openid4vp";
```

## Supported Environments

This library is platform agnostic and support Node.JS, React Native and browsers out of the box, as long as it provides an implementation of `URL` and `URLSearchParams`. However because of this it is required to provide some callbacks for simple things like hashing, generate random bytes, etc. If no global `fetch` is available in your environment, this also need to be provided in the callbacks.

## Contributing

Is there something you'd like to fix or add? Great, we love community
contributions! To get involved, please follow our [contribution guidelines](./CONTRIBUTING.md).

## License

This project is licensed under the Apache License Version 2.0 (Apache-2.0).

## Credits

This library was initially created by [Animo](https://github.com) as part of the [SPRIN-D EUDI Wallet Prototypes Funke](https://www.sprind.org/en/impulses/challenges/eudi-wallet-prototypes).
