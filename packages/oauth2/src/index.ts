export type {
  AccessTokenErrorResponse,
  AccessTokenResponse,
} from './access-token/z-access-token'

// Re-export some types from utils (we don't want people depending on that lib)
export { type HttpMethod, getGlobalConfig, setGlobalConfig, type Oid4vcTsConfig } from '@openid4vc/utils'

export {
  Oauth2ErrorCodes,
  type Oauth2ErrorResponse,
  zOauth2ErrorResponse,
} from './common/z-oauth2-error'
export { calculateJwkThumbprint, type CalculateJwkThumbprintOptions } from './common/jwk/jwk-thumbprint'

// TODO: should we move this to oauth2-utils?
export { isJwkInSet } from './common/jwk/jwks'

export { type Jwk, type JwkSet, zJwk } from './common/jwk/z-jwk'
export type { AccessTokenProfileJwtPayload } from './access-token/z-access-token-jwt'

export {
  verifyJwt,
  type VerifyJwtOptions,
} from './common/jwt/verify-jwt'
export {
  DecodeJwtOptions,
  DecodeJwtResult,
  decodeJwt,
  jwtHeaderFromJwtSigner,
  jwtSignerFromJwt,
} from './common/jwt/decode-jwt'
export {
  JwtSigner,
  JwtSignerCustom,
  JwtSignerDid,
  JwtSignerJwk,
  JwtSignerX5c,
  JwtSignerWithJwk,
  zJwtHeader,
  zJwtPayload,
  zCompactJwt,
} from './common/jwt/z-jwt'

export type { RequestDpopOptions } from './dpop/dpop'
export type { RequestClientAttestationOptions } from './client-attestation/client-attestation-pop'
export type {
  ClientAttestationJwtHeader,
  ClientAttestationJwtPayload,
  ClientAttestationPopJwtHeader,
  ClientAttestationPopJwtPayload,
} from './client-attestation/z-client-attestation'

export { Oauth2Error, Oauth2ErrorOptions } from './error/Oauth2Error'
export { Oauth2JwtVerificationError } from './error/Oauth2JwtVerificationError'
export { Oauth2JwtParseError } from './error/Oauth2JwtParseError'
export {
  Oauth2ResourceUnauthorizedError,
  type WwwAuthenticateHeaderChallenge,
} from './error/Oauth2ResourceUnauthorizedError'
export { InvalidFetchResponseError } from '@openid4vc/utils'
export { Oauth2ClientErrorResponseError } from './error/Oauth2ClientErrorResponseError'
export { Oauth2ClientAuthorizationChallengeError } from './error/Oauth2ClientAuthorizationChallengeError'
export { Oauth2ServerErrorResponseError } from './error/Oauth2ServerErrorResponseError'

export type {
  AuthorizationChallengeRequest,
  AuthorizationChallengeErrorResponse,
  AuthorizationChallengeResponse,
} from './authorization-challenge/z-authorization-challenge'
export {
  AuthorizationServerMetadata,
  // Ideally we don't export this, but it's needed in oid4vci
  zAuthorizationServerMetadata,
} from './metadata/authorization-server/z-authorization-server-metadata'
export {
  getAuthorizationServerMetadataFromList,
  fetchAuthorizationServerMetadata,
} from './metadata/authorization-server/authorization-server-metadata'
export { fetchJwks } from './metadata/fetch-jwks-uri'
export { fetchWellKnownMetadata } from './metadata/fetch-well-known-metadata'

export type { TokenIntrospectionResponse } from './access-token/z-token-introspection'

export { SupportedAuthenticationScheme } from './access-token/verify-access-token'
export type { VerifyAccessTokenRequestReturn } from './access-token/verify-access-token-request'
export type {
  RetrieveAuthorizationCodeAccessTokenOptions,
  RetrievePreAuthorizedCodeAccessTokenOptions,
} from './access-token/retrieve-access-token'
export type { CreateAuthorizationRequestUrlOptions } from './authorization-request/create-authorization-request'
export {
  resourceRequest,
  type ResourceRequestOptions,
  type ResourceRequestResponseNotOk,
  type ResourceRequestResponseOk,
} from './resource-request/make-resource-request'
export {
  type VerifyResourceRequestOptions,
  verifyResourceRequest,
} from './resource-request/verify-resource-request'

export type {
  CallbackContext,
  GenerateRandomCallback,
  HashCallback,
  SignJwtCallback,
  VerifyJwtCallback,
} from './callbacks'
export { HashAlgorithm } from './callbacks'

export {
  ClientAuthenticationCallbackOptions,
  ClientAuthenticationCallback,
  type ClientAuthenticationDynamicOptions,
  clientAuthenticationDynamic,
  clientAuthenticationNone,
  type ClientAuthenticationClientSecretBasicOptions,
  clientAuthenticationClientSecretBasic,
  type ClientAuthenticationClientSecretPostOptions,
  clientAuthenticationClientSecretPost,
} from './client-authentication'

export { type Oauth2AuthorizationServerOptions, Oauth2AuthorizationServer } from './Oauth2AuthorizationServer'
export { type Oauth2ResourceServerOptions, Oauth2ResourceServer } from './Oauth2ResourceServer'
export { type Oauth2ClientOptions, Oauth2Client } from './Oauth2Client'

export { PkceCodeChallengeMethod, CreatePkceReturn } from './pkce'
export {
  type AuthorizationCodeGrantIdentifier,
  zAuthorizationCodeGrantIdentifier,
  authorizationCodeGrantIdentifier,
  type PreAuthorizedCodeGrantIdentifier,
  zPreAuthorizedCodeGrantIdentifier,
  preAuthorizedCodeGrantIdentifier,
  type RefreshTokenGrantIdentifier,
  zRefreshTokenGrantIdentifier,
  refreshTokenGrantIdentifier,
} from './z-grant-type'
