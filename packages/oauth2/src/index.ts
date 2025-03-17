export type {
  AccessTokenErrorResponse,
  AccessTokenResponse,
} from './access-token/z-access-token'

// Re-export some types from utils (we don't want people depending on that lib)
export { getGlobalConfig, setGlobalConfig, type HttpMethod, type Oid4vcTsConfig } from '@openid4vc/utils'

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
  decodeJwt,
  DecodeJwtOptions,
  DecodeJwtResult,
  jwtHeaderFromJwtSigner,
  jwtSignerFromJwt,
} from './common/jwt/decode-jwt'

export type { JweEncryptor } from './common/jwt/z-jwt'

export {
  JwtSigner,
  JwtSignerCustom,
  JwtSignerDid,
  JwtSignerJwk,
  JwtSignerWithJwk,
  JwtSignerX5c,
  zJwtHeader,
  zJwtPayload,
  zCompactJwt,
} from './common/jwt/z-jwt'

export { zCompactJwe } from './common/jwt/z-jwe'

export type { RequestClientAttestationOptions } from './client-attestation/client-attestation-pop'
export {
  createClientAttestationJwt,
  type CreateClientAttestationJwtOptions,
} from './client-attestation/clent-attestation'
export type {
  ClientAttestationJwtHeader,
  ClientAttestationJwtPayload,
  ClientAttestationPopJwtHeader,
  ClientAttestationPopJwtPayload,
} from './client-attestation/z-client-attestation'
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
} from './authorization-challenge/z-authorization-challenge'
export type {
  VerifyAuthorizationChallengeRequestOptions,
  VerifyAuthorizationChallengeRequestReturn,
} from './authorization-challenge/verify-authorization-challenge-request'
export type {
  ParseAuthorizationChallengeRequestOptions,
  ParseAuthorizationChallengeRequestResult,
} from './authorization-challenge/parse-authorization-challenge-request'
export {
  fetchAuthorizationServerMetadata,
  getAuthorizationServerMetadataFromList,
} from './metadata/authorization-server/authorization-server-metadata'
export {
  AuthorizationServerMetadata,
  zAuthorizationServerMetadata,
  // Ideally we don't export this, but it's needed in openid4vci
} from './metadata/authorization-server/z-authorization-server-metadata'
export { fetchJwks } from './metadata/fetch-jwks-uri'
export { fetchWellKnownMetadata } from './metadata/fetch-well-known-metadata'

export type { TokenIntrospectionResponse } from './access-token/z-token-introspection'

export type {
  RetrieveAuthorizationCodeAccessTokenOptions,
  RetrievePreAuthorizedCodeAccessTokenOptions,
} from './access-token/retrieve-access-token'
export { SupportedAuthenticationScheme } from './access-token/verify-access-token'
export type { VerifyAccessTokenRequestReturn } from './access-token/verify-access-token-request'
export type { CreateAuthorizationRequestUrlOptions } from './authorization-request/create-authorization-request'
export type {
  CreatePushedAuthorizationErrorResponseOptions,
  CreatePushedAuthorizationResponseOptions,
} from './authorization-request/create-pushed-authorization-response'
export type {
  ParsePushedAuthorizationRequestOptions,
  ParsePushedAuthorizationRequestResult,
} from './authorization-request/parse-pushed-authorization-request'
export type {
  VerifyPushedAuthorizationRequestOptions,
  VerifyPushedAuthorizationRequestReturn,
} from './authorization-request/verify-pushed-authorization-request'
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
  DecryptJweCallback,
  DecryptJweCallbackOptions,
  EncryptJweCallback,
} from './callbacks'

export {
  ClientAuthenticationCallback,
  ClientAuthenticationCallbackOptions,
  clientAuthenticationClientSecretBasic,
  clientAuthenticationClientSecretPost,
  clientAuthenticationDynamic,
  clientAuthenticationNone,
  clientAuthenticationClientAttestationJwt,
  type ClientAuthenticationClientSecretBasicOptions,
  type ClientAuthenticationClientSecretPostOptions,
  type ClientAuthenticationDynamicOptions,
  type ClientAuthenticationClientAttestationJwtOptions,
} from './client-authentication'

export { Oauth2AuthorizationServer, type Oauth2AuthorizationServerOptions } from './Oauth2AuthorizationServer'
export { Oauth2Client, type Oauth2ClientOptions } from './Oauth2Client'
export { Oauth2ResourceServer, type Oauth2ResourceServerOptions } from './Oauth2ResourceServer'

export { CreatePkceReturn, PkceCodeChallengeMethod } from './pkce'

export {
  type PreAuthorizedCodeGrantIdentifier,
  zPreAuthorizedCodeGrantIdentifier,
  preAuthorizedCodeGrantIdentifier,
  type RefreshTokenGrantIdentifier,
  zRefreshTokenGrantIdentifier,
  refreshTokenGrantIdentifier,
  type AuthorizationCodeGrantIdentifier,
  zAuthorizationCodeGrantIdentifier,
  authorizationCodeGrantIdentifier,
} from './z-grant-type'

export { JwtHeader, JwtPayload } from './common/jwt/z-jwt'
export { verifyJwt } from './common/jwt/verify-jwt'
export { zJwkSet } from './common/jwk/z-jwk'
export { decodeJwtHeader, DecodeJwtHeaderResult } from './common/jwt/decode-jwt-header'

export { zAlgValueNotNone } from './common/z-common'
