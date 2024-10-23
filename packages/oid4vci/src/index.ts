export { Oid4vciClient, Oid4vciClientOptions } from './client'

export type {
  CallbackContext,
  GenerateRandomCallback,
  HashCallback,
  SignJwtCallback,
  VerifyJwtCallback,
} from './callbacks'
export { HashAlgorithm } from './callbacks'

export { Oid4vciDraftVersion } from './versions/draft-version'

export type {
  CredentialConfigurationSupported,
  CredentialConfigurationSupportedWithFormat,
  CredentialIssuerMetadata,
  StrictCredentialConfigurationSupported,
} from './metadata/credential-issuer/v-credential-issuer-metadata'

export {
  extractScopesForCredentialConfigurationIds,
  type ExtractScopesForCredentialConfigurationIdsOptions,
} from './metadata/credential-issuer/credential-configurations'

export type { AuthorizationServerMetadata } from './metadata/authorization-server/v-authorization-server-metadata'

export {
  AccessTokenErrorResponse,
  AccessTokenResponse,
} from './authorization/access-token/v-access-token'

export {
  type CredentialOfferObject,
  authorizationCodeGrantIdentifier,
  preAuthorizedCodeGrantIdentifier,
} from './credential-offer/v-credential-offer'

export type {
  CredentialRequestWithFormats,
  CredentialRequest,
  StrictCredentialRequest,
} from './credential-request/v-credential-request'
export type { CredentialErrorResponse, CredentialResponse } from './credential-request/v-credential-response'

export { Oid4vcError, Oid4vcErrorOptions } from './error/Oid4vcError'
export { Oid4vcInvalidFetchResponseError } from './error/Oid4vcInvalidFetchResponseError'
export { Oid4vcJsonParseError } from './error/Oid4vcJsonParseError'
export { Oid4vcOauthErrorResponseError } from './error/Oid4vcOauthErrorResponseError'
export { Oid4vcValidationError } from './error/Oid4vcValidationError'

export type {
  JwtVcJsonFormatIdentifier,
  JwtVcJsonLdFormatIdentifier,
  LdpVcFormatIdentifier,
  MsoMdocFormatIdentifier,
  SdJwtVcFormatIdentifier,
} from './formats/credential'

export type { IssuerMetadataResult } from './metadata/fetch-issuer-metadata'

export { JwtProofTypeIdentifier } from './formats/proof-type/jwt/v-jwt-proof-type'
