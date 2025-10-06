export { determineAuthorizationServerForCredentialOffer } from './credential-offer/credential-offer'

export type {
  CredentialOfferObject,
  CredentialOfferPreAuthorizedCodeGrantTxCode,
  CredentialOfferGrants,
  CredentialOfferAuthorizationCodeGrant,
  CredentialOfferPreAuthorizedCodeGrant,
} from './credential-offer/z-credential-offer'

// Re-export some types from utils (we don't want people depending on that lib)
export { getGlobalConfig, setGlobalConfig, type Oid4vcTsConfig } from '@openid4vc/utils'

export type { ParseCredentialRequestReturn } from './credential-request/parse-credential-request'
export type {
  RetrieveCredentialsResponseNotOk,
  RetrieveCredentialsResponseOk,
} from './credential-request/retrieve-credentials'
export type {
  CredentialRequestWithFormats,
  CredentialRequest,
  CredentialRequestFormatSpecific,
  DeferredCredentialRequest,
} from './credential-request/z-credential-request'
export type {
  CredentialErrorResponse,
  CredentialResponse,
  DeferredCredentialResponse,
} from './credential-request/z-credential-response'
export {
  type GetCredentialConfigurationsMatchingRequestFormatOptions,
  getCredentialConfigurationsMatchingRequestFormat,
} from './credential-request/credential-request-configurations'

export { Openid4vciError, type Openid4vciErrorOptions } from './error/Openid4vciError'
export { Openid4vciRetrieveCredentialsError } from './error/Openid4vciRetrieveCredentialsError'
export { Openid4vciSendNotificationError } from './error/Openid4vciSendNotificationError'

export type { NonceResponse } from './nonce/z-nonce'

export type { SendNotificationResponseNotOk, SendNotificationResponseOk } from './notification/notification'
export type { NotificationErrorResponse, NotificationEvent } from './notification/z-notification'
export type {
  CredentialRequestJwtProofTypeHeader,
  CredentialRequestJwtProofTypePayload,
} from './formats/proof-type/jwt/z-jwt-proof-type'
export type { JwtProofTypeIdentifier, ProofTypeIdentifier } from './formats/proof-type'

export {
  createKeyAttestationJwt,
  verifyKeyAttestationJwt,
  parseKeyAttestationJwt,
  type ParseKeyAttestationJwtOptions,
  type CreateKeyAttestationJwtOptions,
  type VerifyKeyAttestationJwtOptions,
  type VerifyKeyAttestationJwtReturn,
} from './key-attestation/key-attestation'

export type {
  JwtVcJsonFormatIdentifier,
  JwtVcJsonLdFormatIdentifier,
  LdpVcFormatIdentifier,
  MsoMdocFormatIdentifier,
  LegacySdJwtVcFormatIdentifier,
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
} from './metadata/credential-issuer/z-credential-issuer-metadata'

export {
  extractScopesForCredentialConfigurationIds,
  type ExtractScopesForCredentialConfigurationIdsOptions,
  credentialsSupportedToCredentialConfigurationsSupported,
} from './metadata/credential-issuer/credential-configurations'

export { Openid4vciClient, type Openid4vciClientOptions, AuthorizationFlow } from './Openid4vciClient'
export { Openid4vciIssuer, type Openid4vciIssuerOptions } from './Openid4vciIssuer'
export { Openid4vciWalletProvider, type Openid4vciWalletProviderOptions } from './Openid4vciWalletProvider'

export { Openid4vciDraftVersion } from './version'
