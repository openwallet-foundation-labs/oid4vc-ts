export type {
  CredentialOfferObject,
  CredentialOfferPreAuthorizedCodeGrantTxCode,
} from './credential-offer/v-credential-offer'

export type { ParseCredentialRequestReturn } from './credential-request/parse-credential-request'
export type {
  CredentialRequestWithFormats,
  CredentialRequest,
  CredentialRequestFormatSpecific,
} from './credential-request/v-credential-request'
export type { CredentialErrorResponse, CredentialResponse } from './credential-request/v-credential-response'
export {
  type GetCredentialConfigurationsMatchingRequestFormatOptions,
  getCredentialConfigurationsMatchingRequestFormat,
} from './credential-request/credential-request-configurations'

export { Oid4vciError, Oid4vciErrorOptions } from './error/Oid4vcError'

export type {
  CredentialRequestJwtProofTypeHeader,
  CredentialRequestJwtProofTypePayload,
} from './formats/proof-type/jwt/v-jwt-proof-type'
export type { JwtProofTypeIdentifier, ProofTypeIdentifier } from './formats/proof-type'

export type {
  JwtVcJsonFormatIdentifier,
  JwtVcJsonLdFormatIdentifier,
  LdpVcFormatIdentifier,
  MsoMdocFormatIdentifier,
  SdJwtVcFormatIdentifier,
  CredentialFormatIdentifier,
} from './formats/credential'

export type { IssuerMetadataResult } from './metadata/fetch-issuer-metadata'

export type {
  CredentialConfigurationSupported,
  CredentialConfigurationsSupported,
  CredentialConfigurationSupportedWithFormats,
  CredentialConfigurationsSupportedWithFormats,
  CredentialIssuerMetadata,
  CredentialIssuerMetadataDisplayEntry,
} from './metadata/credential-issuer/v-credential-issuer-metadata'

export {
  extractScopesForCredentialConfigurationIds,
  type ExtractScopesForCredentialConfigurationIdsOptions,
} from './metadata/credential-issuer/credential-configurations'

export { Oid4vciClient, type Oid4vciClientOptions } from './Oid4vciClient'
export { Oid4vciIssuer, type Oid4vciIssuerOptions } from './Oid4vciIssuer'

export { Oid4vciDraftVersion } from './version'
