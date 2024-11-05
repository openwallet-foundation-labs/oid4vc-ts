export type {
  AccessTokenErrorResponse,
  AccessTokenResponse,
} from './access-token/v-access-token'

export { Oauth2ErrorCodes, type Oauth2ErrorResponse, vOauth2ErrorResponse } from './common/v-oauth2-error'
export { calculateJwkThumbprint, type CalculateJwkThumbprintOptions } from './common/jwk/jwk-thumbprint'
export { type Jwk, type JwkSet, vJwk } from './common/jwk/v-jwk'
export { ContentType } from './common/content-type'

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
  vJwtHeader,
  vJwtPayload,
  vCompactJwt,
} from './common/jwt/v-jwt'

export type {
  RequestDpopOptions,
  ResponseDpopReturn,
} from './dpop/dpop'

export { Oauth2Error, Oauth2ErrorOptions } from './error/Oauth2Error'
export { Oauth2JwtVerificationError } from './error/Oauth2JwtVerificationError'
export {
  Oauth2ResourceUnauthorizedError,
  type WwwAuthenticateHeaderChallenge,
} from './error/Oauth2ResourceUnauthorizedError'
export { Oauth2InvalidFetchResponseError } from './error/Oauth2InvalidFetchResponseError'
export { Oauth2ClientErrorResponseError } from './error/Oauth2ClientErrorResponseError'
export { Oauth2ClientAuthorizationChallengeError } from './error/Oauth2ClientAuthorizationChallengeError'
export { Oauth2ServerErrorResponseError } from './error/Oauth2ServerErrorResponseError'

export {
  AuthorizationServerMetadata,
  // Ideally we don't export this, but it's needed in oid4vci
  vAuthorizationServerMetadata,
} from './metadata/authorization-server/v-authorization-server-metadata'
export {
  getAuthorizationServerMetadataFromList,
  fetchAuthorizationServerMetadata,
} from './metadata/authorization-server/authorization-server-metadata'
export { fetchJwks } from './metadata/fetch-jwks-uri'
export { fetchWellKnownMetadata } from './metadata/fetch-well-known-metadata'

export { SupportedAuthenticationScheme } from './access-token/verify-access-token'
export type {
  RetrieveAuthorizationCodeAccessTokenOptions,
  RetrievePreAuthorizedCodeAccessTokenOptions,
} from './access-token/retrieve-access-token'
export type { CreateAuthorizationRequestUrlOptions } from './authorization-request/create-authorization-request'
export { resourceRequestWithDpopRetry, type ResourceRequestOptions } from './resource-request/make-resource-request'
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
  GetClientAuthenticationOptions,
  ClientAuthenticationCallback,
  clientAuthenticationNone,
  type ClientAuthenticationClientSecretBasicOptions,
  clientAuthenticationClientSecretBasic,
  type ClientAuthenticationClientSecretPostOptions,
  clientAuthenticationClientSecretPost,
} from './client-authentication'

export { type Oauth2AuthorizationServerOptions, Oauth2AuthorizationServer } from './Oauth2AuthorizationServer'
export { type Oauth2ResourceServerOptions, Oauth2ResourceServer } from './Oauth2ResourceServer'
export { type Oauth2ClientOptions, Oauth2Client } from './Oauth2Client'

export { PkceCodeChallengeMethod } from './pkce'
export {
  type AuthorizationCodeGrantIdentifier,
  vAuthorizationCodeGrantIdentifier,
  authorizationCodeGrantIdentifier,
  type PreAuthorizedCodeGrantIdentifier,
  vPreAuthorizedCodeGrantIdentifier,
  preAuthorizedCodeGrantIdentifier,
} from './v-grant-type'