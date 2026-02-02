// Re-export some types from utils (we don't want people depending on that lib)
export { getGlobalConfig, type Oid4vcTsConfig, setGlobalConfig } from '@openid4vc/utils'
export { determineAuthorizationServerForCredentialOffer } from './credential-offer/credential-offer'
export type {
  CredentialOfferAuthorizationCodeGrant,
  CredentialOfferGrants,
  CredentialOfferObject,
  CredentialOfferPreAuthorizedCodeGrant,
  CredentialOfferPreAuthorizedCodeGrantTxCode,
} from './credential-offer/z-credential-offer'
export {
  type GetCredentialConfigurationsMatchingRequestFormatOptions,
  getCredentialConfigurationsMatchingRequestFormat,
} from './credential-request/credential-request-configurations'
export type { ParseCredentialRequestReturn } from './credential-request/parse-credential-request'
export type {
  RetrieveCredentialsResponseNotOk,
  RetrieveCredentialsResponseOk,
} from './credential-request/retrieve-credentials'
export type {
  CredentialRequest,
  CredentialRequestFormatSpecific,
  CredentialRequestWithFormats,
  DeferredCredentialRequest,
} from './credential-request/z-credential-request'
export type { CredentialResponseEncryption } from './credential-request/z-credential-request-common'
export type {
  CredentialErrorResponse,
  CredentialResponse,
  DeferredCredentialResponse,
} from './credential-request/z-credential-response'

export { Openid4vciClientInteractiveAuthorizationError } from './error/Openid4vciClientInteractiveAuthorizationError'
export { Openid4vciError, type Openid4vciErrorOptions } from './error/Openid4vciError'
export { Openid4vciRetrieveCredentialsError } from './error/Openid4vciRetrieveCredentialsError'
export { Openid4vciSendNotificationError } from './error/Openid4vciSendNotificationError'
export type {
  CredentialFormatIdentifier,
  JwtVcJsonFormatIdentifier,
  JwtVcJsonLdFormatIdentifier,
  LdpVcFormatIdentifier,
  LegacySdJwtVcFormatIdentifier,
  MsoMdocFormatIdentifier,
} from './formats/credential'
export type { JwtProofTypeIdentifier, ProofTypeIdentifier } from './formats/proof-type'
export type {
  CredentialRequestJwtProofTypeHeader,
  CredentialRequestJwtProofTypePayload,
} from './formats/proof-type/jwt/z-jwt-proof-type'
export {
  type CreateInteractiveAuthorizationCodeResponseOptions,
  type CreateInteractiveAuthorizationErrorResponseOptions,
  type CreateInteractiveAuthorizationOpenid4vpInteractionOptions,
  type CreateInteractiveAuthorizationRedirectToWebInteractionOptions,
  createInteractiveAuthorizationCodeResponse,
  createInteractiveAuthorizationErrorResponse,
  createInteractiveAuthorizationOpenid4vpInteraction,
  createInteractiveAuthorizationRedirectToWebInteraction,
} from './interactive-authorization/create-interactive-authorization-response'
export {
  InteractiveAuthorizationRequestType,
  type ParseInteractiveAuthorizationFollowUpRequestResult,
  type ParseInteractiveAuthorizationInitialRequestResult,
  type ParseInteractiveAuthorizationRequestOptions,
  parseInteractiveAuthorizationRequest,
} from './interactive-authorization/parse-interactive-authorization-request'
export {
  type SendInteractiveAuthorizationRequestOptions,
  sendInteractiveAuthorizationRequest,
} from './interactive-authorization/send-interactive-authorization-request'
export {
  type VerifyInteractiveAuthorizationInitialRequestOptions,
  type VerifyInteractiveAuthorizationInitialRequestReturn,
  verifyInteractiveAuthorizationInitialRequest,
} from './interactive-authorization/verify-interactive-authorization-request'
export type {
  InteractiveAuthorizationCodeResponse,
  InteractiveAuthorizationFollowUpRequest,
  InteractiveAuthorizationInitialRequest,
  InteractiveAuthorizationInteractionRequiredResponse,
  InteractiveAuthorizationOpenid4vpPresentationResponse,
  InteractiveAuthorizationRedirectToWebResponse,
  InteractiveAuthorizationRequest,
  InteractiveAuthorizationResponse,
} from './interactive-authorization/z-interactive-authorization'
export {
  type CreateKeyAttestationJwtOptions,
  createKeyAttestationJwt,
  type ParseKeyAttestationJwtOptions,
  parseKeyAttestationJwt,
  type VerifyKeyAttestationJwtOptions,
  type VerifyKeyAttestationJwtReturn,
  verifyKeyAttestationJwt,
} from './key-attestation/key-attestation'
export {
  credentialsSupportedToCredentialConfigurationsSupported,
  type ExtractScopesForCredentialConfigurationIdsOptions,
  extractScopesForCredentialConfigurationIds,
} from './metadata/credential-issuer/credential-configurations'
export type {
  CredentialConfigurationSupported,
  CredentialConfigurationSupportedWithFormats,
  CredentialConfigurationsSupported,
  CredentialConfigurationsSupportedWithFormats,
  CredentialIssuerMetadata,
  CredentialIssuerMetadataDisplayEntry,
} from './metadata/credential-issuer/z-credential-issuer-metadata'
export type { IssuerMetadataResult } from './metadata/fetch-issuer-metadata'
export type { NonceResponse } from './nonce/z-nonce'
export type { SendNotificationResponseNotOk, SendNotificationResponseOk } from './notification/notification'
export type { NotificationErrorResponse, NotificationEvent } from './notification/z-notification'

export { AuthorizationFlow, Openid4vciClient, type Openid4vciClientOptions } from './Openid4vciClient'
export { Openid4vciIssuer, type Openid4vciIssuerOptions } from './Openid4vciIssuer'
export { Openid4vciWalletProvider, type Openid4vciWalletProviderOptions } from './Openid4vciWalletProvider'

export { Openid4vciDraftVersion, Openid4vciVersion } from './version'
