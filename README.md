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

## Packages

All packages are placed in the [`packages/`](./packages) directory.

| Package                                   | Version                                                                                                                     | Description                                                                   |
| ----------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| [`@animo-id/oid4vci`](./packages/oid4vci) | [![@animo-id/oid4vci version](https://img.shields.io/npm/v/@animo-id/oid4vci)](https://npmjs.com/package/@animo-id/oid4vci) | Implementation of the OpenID for Verifiable Credential Issuance specification |

## Environments

This library tries to be platform agnostic where possible, and has some custom implementations for specific envrionments. Node.JS, Browser and React Native are officially supported, but contributsion for other environments are welcome.

### Browser

Browser environment is supported out of the box.

### Node.JS

Node.JS environment is supported out of the box.

### React Native

Official support for React Native environments is only available for the Hermes JavaScript runtime, not when using JavaScriptCore. Some features have only been added starting from React Native 0.75. If you're using an older version of React Native, you might need to provide certain polyfills.

- `atob` an `btoa` are used for base64 encoding and decoding. These methods have only been added in Hermes from React Native 0.74 (and properly since 0.74.1 due to a bug).
  - In older versions of React Native you can add support using the [`base-64`](https://www.npmjs.com/package/base-64) library, and apply the polyfill as described in [this StackOverflow answer](https://stackoverflow.com/a/51525605). Make sure to also import this polyfill in the root of your project.
- `TextEncoding` is used to transform between string and Uint8Array instances. Support for this has only been added to Hermes from React Native 0.75.
  - In older versions of React Native you can add the [`fast-text-encoding`](https://www.npmjs.com/package/fast-text-encoding) polyfill and import this in the root of your project.

## Contributing

Is there something you'd like to fix or add? Great, we love community
contributions! To get involved, please follow our [contribution guidelines](./CONTRIBUTING.md).

## License

This project is licensed under the Apache License Version 2.0 (Apache-2.0).
