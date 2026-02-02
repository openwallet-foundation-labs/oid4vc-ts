// Re-export some types from utils (we don't want people depending on that lib)
export {
  getGlobalConfig,
  type HttpMethod,
  InvalidFetchResponseError,
  type Oid4vcTsConfig,
  setGlobalConfig,
} from '@openid4vc/utils'
export type {
  RetrieveAuthorizationCodeAccessTokenOptions,
  RetrieveClientCredentialsAccessTokenOptions,
  RetrievePreAuthorizedCodeAccessTokenOptions,
} from './access-token/retrieve-access-token'
export { SupportedAuthenticationScheme } from './access-token/verify-access-token'
export type { VerifyAccessTokenRequestReturn } from './access-token/verify-access-token-request'
export type {
  AccessTokenErrorResponse,
  AccessTokenResponse,
} from './access-token/z-access-token'
export type { AccessTokenProfileJwtPayload } from './access-token/z-access-token-jwt'
export type { TokenIntrospectionResponse } from './access-token/z-token-introspection'
export type {
  ParseAuthorizationChallengeRequestOptions,
  ParseAuthorizationChallengeRequestResult,
} from './authorization-challenge/parse-authorization-challenge-request'
export type {
  VerifyAuthorizationChallengeRequestOptions,
  VerifyAuthorizationChallengeRequestReturn,
} from './authorization-challenge/verify-authorization-challenge-request'
export type {
  AuthorizationChallengeErrorResponse,
  AuthorizationChallengeRequest,
  AuthorizationChallengeResponse,
} from './authorization-challenge/z-authorization-challenge'
export type { CreateAuthorizationRequestUrlOptions } from './authorization-request/create-authorization-request'
export type {
  CreatePushedAuthorizationErrorResponseOptions,
  CreatePushedAuthorizationResponseOptions,
} from './authorization-request/create-pushed-authorization-response'
export {
  type ParsePushedAuthorizationRequestOptions,
  type ParsePushedAuthorizationRequestResult,
  parsePushedAuthorizationRequestUriReferenceValue,
} from './authorization-request/parse-pushed-authorization-request'
export type {
  VerifyPushedAuthorizationRequestOptions,
  VerifyPushedAuthorizationRequestReturn,
} from './authorization-request/verify-pushed-authorization-request'
export {
  type PushedAuthorizationRequestUriPrefix,
  pushedAuthorizationRequestUriPrefix,
  zPushedAuthorizationRequestUriPrefix,
} from './authorization-request/z-authorization-request'
export * from './authorization-response'
export type {
  CallbackContext,
  DecryptJweCallback,
  DecryptJweCallbackOptions,
  EncryptJweCallback,
  GenerateRandomCallback,
  HashCallback,
  SignJwtCallback,
  VerifyJwtCallback,
} from './callbacks'
export { HashAlgorithm } from './callbacks'
export {
  type CreateClientAttestationJwtOptions,
  createClientAttestationJwt,
  type VerifiedClientAttestationJwt,
  verifyClientAttestationJwt,
} from './client-attestation/client-attestation'
export type { RequestClientAttestationOptions } from './client-attestation/client-attestation-pop'
export type {
  ClientAttestationJwtHeader,
  ClientAttestationJwtPayload,
  ClientAttestationPopJwtHeader,
  ClientAttestationPopJwtPayload,
} from './client-attestation/z-client-attestation'
export {
  type ClientAuthenticationCallback,
  type ClientAuthenticationCallbackOptions,
  type ClientAuthenticationClientAttestationJwtOptions,
  type ClientAuthenticationClientSecretBasicOptions,
  type ClientAuthenticationClientSecretPostOptions,
  type ClientAuthenticationDynamicOptions,
  type ClientAuthenticationNoneOptions,
  clientAuthenticationAnonymous,
  clientAuthenticationClientAttestationJwt,
  clientAuthenticationClientSecretBasic,
  clientAuthenticationClientSecretPost,
  clientAuthenticationDynamic,
  clientAuthenticationNone,
  SupportedClientAuthenticationMethod,
} from './client-authentication'
export {
  fullySpecifiedCoseAlgorithmArrayToJwaSignatureAlgorithmArray,
  fullySpecifiedCoseAlgorithmToJwaSignatureAlgorithm,
  jwaSignatureAlgorithmArrayToFullySpecifiedCoseAlgorithmArray,
  jwaSignatureAlgorithmToFullySpecifiedCoseAlgorithm,
} from './common/algorithm'
export { type CalculateJwkThumbprintOptions, calculateJwkThumbprint } from './common/jwk/jwk-thumbprint'
// TODO: should we move this to oauth2-utils?
export { isJwkInSet } from './common/jwk/jwks'
export { type Jwk, type JwkSet, zJwk, zJwkSet } from './common/jwk/z-jwk'
export {
  type DecodeJwtOptions,
  type DecodeJwtResult,
  decodeJwt,
  jwtHeaderFromJwtSigner,
  jwtSignerFromJwt,
} from './common/jwt/decode-jwt'
export { type DecodeJwtHeaderResult, decodeJwtHeader } from './common/jwt/decode-jwt-header'
export { verifyJwt } from './common/jwt/verify-jwt'
export { zCompactJwe } from './common/jwt/z-jwe'
export type { JweEncryptor, JwtHeader, JwtPayload } from './common/jwt/z-jwt'
export {
  type JwtSigner,
  type JwtSignerCustom,
  type JwtSignerDid,
  type JwtSignerJwk,
  type JwtSignerWithJwk,
  type JwtSignerX5c,
  zCompactJwt,
  zJwtHeader,
  zJwtPayload,
} from './common/jwt/z-jwt'
export { type RequestLike, zAlgValueNotNone } from './common/z-common'
export {
  Oauth2ErrorCodes,
  type Oauth2ErrorResponse,
  zOauth2ErrorResponse,
} from './common/z-oauth2-error'
export type { RequestDpopOptions } from './dpop/dpop'
export { Oauth2ClientAuthorizationChallengeError } from './error/Oauth2ClientAuthorizationChallengeError'
export { Oauth2ClientErrorResponseError } from './error/Oauth2ClientErrorResponseError'
export { Oauth2Error, type Oauth2ErrorOptions } from './error/Oauth2Error'
export { Oauth2JwtParseError } from './error/Oauth2JwtParseError'
export { Oauth2JwtVerificationError } from './error/Oauth2JwtVerificationError'
export {
  Oauth2ResourceUnauthorizedError,
  type WwwAuthenticateHeaderChallenge,
} from './error/Oauth2ResourceUnauthorizedError'
export { Oauth2ServerErrorResponseError } from './error/Oauth2ServerErrorResponseError'
export * from './id-token'
export type { CreateJarAuthorizationRequestOptions } from './jar/create-jar-authorization-request'
export { createJarAuthorizationRequest } from './jar/create-jar-authorization-request'
export type { JarAuthorizationRequest } from './jar/z-jar-authorization-request'
export {
  validateJarRequestParams,
  zJarAuthorizationRequest,
} from './jar/z-jar-authorization-request'
export type { JarRequestObjectPayload } from './jar/z-jar-request-object'
export {
  jwtAuthorizationRequestJwtHeaderTyp,
  signedAuthorizationRequestJwtHeaderTyp,
  zJarRequestObjectPayload,
} from './jar/z-jar-request-object'
export {
  fetchAuthorizationServerMetadata,
  getAuthorizationServerMetadataFromList,
} from './metadata/authorization-server/authorization-server-metadata'
export {
  type AuthorizationServerMetadata,
  zAuthorizationServerMetadata,
  // Ideally we don't export this, but it's needed in openid4vci
} from './metadata/authorization-server/z-authorization-server-metadata'
export { fetchJwks } from './metadata/fetch-jwks-uri'
export { fetchWellKnownMetadata } from './metadata/fetch-well-known-metadata'
export { Oauth2AuthorizationServer, type Oauth2AuthorizationServerOptions } from './Oauth2AuthorizationServer'
export { Oauth2Client, type Oauth2ClientOptions } from './Oauth2Client'
export { Oauth2ResourceServer, type Oauth2ResourceServerOptions } from './Oauth2ResourceServer'
export { type CreatePkceReturn, PkceCodeChallengeMethod } from './pkce'
export {
  type ResourceRequestOptions,
  type ResourceRequestResponseNotOk,
  type ResourceRequestResponseOk,
  resourceRequest,
} from './resource-request/make-resource-request'
export {
  type VerifyResourceRequestOptions,
  verifyResourceRequest,
} from './resource-request/verify-resource-request'
export {
  type AuthorizationCodeGrantIdentifier,
  authorizationCodeGrantIdentifier,
  defaultGrantTypesSupported,
  getGrantTypesSupported,
  type ClientCredentialsGrantIdentifier,
  clientCredentialsGrantIdentifier,
  type PreAuthorizedCodeGrantIdentifier,
  preAuthorizedCodeGrantIdentifier,
  type RefreshTokenGrantIdentifier,
  refreshTokenGrantIdentifier,
  zAuthorizationCodeGrantIdentifier,
  zClientCredentialsGrantIdentifier,
  zPreAuthorizedCodeGrantIdentifier,
  zRefreshTokenGrantIdentifier,
} from './z-grant-type'
