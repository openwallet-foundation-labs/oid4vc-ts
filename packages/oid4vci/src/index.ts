export type {
  CredentialOfferObject,
  CredentialOfferPreAuthorizedCodeGrantTxCode,
} from './credential-offer/v-credential-offer'

// Re-export some types from utils (we don't want people depending on that lib)
export { getGlobalConfig, setGlobalConfig, type Oid4vcTsConfig } from '@animo-id/oauth2-utils'

export type { ParseCredentialRequestReturn } from './credential-request/parse-credential-request'
export type {
  RetrieveCredentialsResponseNotOk,
  RetrieveCredentialsResponseOk,
} from './credential-request/retrieve-credentials'
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

export { Oid4vciError, Oid4vciErrorOptions } from './error/Oid4vciError'
export { Oid4vciRetrieveCredentialsError } from './error/Oid4vciRetrieveCredentialsError'
export { Oid4vciSendNotificationError } from './error/Oid4vciSendNotificationError'

export type { SendNotificationResponseNotOk, SendNotificationResponseOk } from './notification/notification'
export type { NotificationErrorResponse, NotificationEvent } from './notification/v-notification'
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

export { Oid4vciClient, type Oid4vciClientOptions, AuthorizationFlow } from './Oid4vciClient'
export { Oid4vciIssuer, type Oid4vciIssuerOptions } from './Oid4vciIssuer'

export { Oid4vciDraftVersion } from './version'
