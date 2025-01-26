export type {
  AccessTokenErrorResponse,
  AccessTokenResponse,
} from './access-token/v-access-token'

// Re-export some types from utils (we don't want people depending on that lib)
export { getGlobalConfig, setGlobalConfig, type HttpMethod, type Oid4vcTsConfig } from '@openid4vc/utils'

export { calculateJwkThumbprint, type CalculateJwkThumbprintOptions } from './common/jwk/jwk-thumbprint'
export { Oauth2ErrorCodes, vOauth2ErrorResponse, type Oauth2ErrorResponse } from './common/v-oauth2-error'

// TODO: should we move this to oauth2-utils?
export { isJwkInSet } from './common/jwk/jwks'

export type { AccessTokenProfileJwtPayload } from './access-token/v-access-token-jwt'
export { decodeJwtHeader } from './common/jwt/decode-jwt-header'
export { vCompactJwe } from './common/jwe/v-jwe'
export { vJwk, type Jwk, type JwkSet } from './common/jwk/v-jwk'

export {
  decodeJwt,
  DecodeJwtOptions,
  DecodeJwtResult,
  jwtHeaderFromJwtSigner,
  jwtSignerFromJwt,
} from './common/jwt/decode-jwt'

export type { JweEncryptor } from './common/jwt/v-jwt'

export {
  JwtSigner,
  JwtSignerCustom,
  JwtSignerDid,
  JwtSignerJwk,
  JwtSignerWithJwk,
  JwtSignerX5c,
  vCompactJwt,
  vJwtHeader,
  vJwtPayload,
} from './common/jwt/v-jwt'
export {
  verifyJwt,
  type VerifyJwtOptions,
} from './common/jwt/verify-jwt'

export type { RequestClientAttestationOptions } from './client-attestation/client-attestation-pop'
export type {
  ClientAttestationJwtHeader,
  ClientAttestationJwtPayload,
  ClientAttestationPopJwtHeader,
  ClientAttestationPopJwtPayload,
} from './client-attestation/v-client-attestation'
export type { RequestDpopOptions } from './dpop/dpop'

export { InvalidFetchResponseError } from '@openid4vc/utils'
export { Oauth2ClientAuthorizationChallengeError } from './error/Oauth2ClientAuthorizationChallengeError'
export { Oauth2ClientErrorResponseError } from './error/Oauth2ClientErrorResponseError'
export { Oauth2Error, Oauth2ErrorOptions } from './error/Oauth2Error'
export { Oauth2JwtParseError } from './error/Oauth2JwtParseError'
export { Oauth2JwtVerificationError } from './error/Oauth2JwtVerificationError'
export {
  Oauth2ResourceUnauthorizedError,
  type WwwAuthenticateHeaderChallenge,
} from './error/Oauth2ResourceUnauthorizedError'
export { Oauth2ServerErrorResponseError } from './error/Oauth2ServerErrorResponseError'

export type {
  AuthorizationChallengeErrorResponse,
  AuthorizationChallengeRequest,
  AuthorizationChallengeResponse,
} from './authorization-challenge/v-authorization-challenge'
export {
  fetchAuthorizationServerMetadata,
  getAuthorizationServerMetadataFromList,
} from './metadata/authorization-server/authorization-server-metadata'
export {
  AuthorizationServerMetadata,
  // Ideally we don't export this, but it's needed in oid4vci
  vAuthorizationServerMetadata,
} from './metadata/authorization-server/v-authorization-server-metadata'
export { fetchJwks } from './metadata/fetch-jwks-uri'
export { fetchWellKnownMetadata } from './metadata/fetch-well-known-metadata'

export type { TokenIntrospectionResponse } from './access-token/v-token-introspection'

export type {
  RetrieveAuthorizationCodeAccessTokenOptions,
  RetrievePreAuthorizedCodeAccessTokenOptions,
} from './access-token/retrieve-access-token'
export { SupportedAuthenticationScheme } from './access-token/verify-access-token'
export type { VerifyAccessTokenRequestReturn } from './access-token/verify-access-token-request'
export type { CreateAuthorizationRequestUrlOptions } from './authorization-request/create-authorization-request'
export {
  resourceRequest,
  type ResourceRequestOptions,
  type ResourceRequestResponseNotOk,
  type ResourceRequestResponseOk,
} from './resource-request/make-resource-request'
export {
  verifyResourceRequest,
  type VerifyResourceRequestOptions,
} from './resource-request/verify-resource-request'

export { HashAlgorithm } from './callbacks'
export type {
  CallbackContext,
  GenerateRandomCallback,
  HashCallback,
  SignJwtCallback,
  VerifyJwtCallback,
} from './callbacks'

export {
  ClientAuthenticationCallback,
  ClientAuthenticationCallbackOptions,
  clientAuthenticationClientSecretBasic,
  clientAuthenticationClientSecretPost,
  clientAuthenticationDynamic,
  clientAuthenticationNone,
  type ClientAuthenticationClientSecretBasicOptions,
  type ClientAuthenticationClientSecretPostOptions,
  type ClientAuthenticationDynamicOptions,
} from './client-authentication'

export { Oauth2AuthorizationServer, type Oauth2AuthorizationServerOptions } from './Oauth2AuthorizationServer'
export { Oauth2Client, type Oauth2ClientOptions } from './Oauth2Client'
export { Oauth2ResourceServer, type Oauth2ResourceServerOptions } from './Oauth2ResourceServer'

export { CreatePkceReturn, PkceCodeChallengeMethod } from './pkce'
export {
  authorizationCodeGrantIdentifier,
  preAuthorizedCodeGrantIdentifier,
  refreshTokenGrantIdentifier,
  vAuthorizationCodeGrantIdentifier,
  vPreAuthorizedCodeGrantIdentifier,
  vRefreshTokenGrantIdentifier,
  type AuthorizationCodeGrantIdentifier,
  type PreAuthorizedCodeGrantIdentifier,
  type RefreshTokenGrantIdentifier,
} from './v-grant-type'

export type { JwtHeader, JwtPayload } from './common/jwt/v-jwt'

export { vJwkSet } from './common/jwk/v-jwk'
