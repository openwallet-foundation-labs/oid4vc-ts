export type { CredentialOfferObject } from './credential-offer/v-credential-offer'

export type {
  CredentialRequestWithFormats,
  CredentialRequest,
} from './credential-request/v-credential-request'
export type { CredentialErrorResponse, CredentialResponse } from './credential-request/v-credential-response'

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
  CredentialConfigurationSupportedWithFormats,
  CredentialIssuerMetadata,
} from './metadata/credential-issuer/v-credential-issuer-metadata'

export {
  extractScopesForCredentialConfigurationIds,
  type ExtractScopesForCredentialConfigurationIdsOptions,
} from './metadata/credential-issuer/credential-configurations'

export { Oid4vciClient, type Oid4vciClientOptions } from './Oid4vciClient'
export { Oid4vciIssuer, type Oid4vciIssuerOptions } from './Oid4vciIssuer'

export { Oid4vciDraftVersion } from './version'
