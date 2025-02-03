import * as v from 'valibot'

export enum Oauth2ErrorCodes {
  ServerError = 'server_error',

  // Resource Indicators
  InvalidTarget = 'invalid_target',

  // Oauth2
  InvalidRequest = 'invalid_request',
  InvalidToken = 'invalid_token',
  InsufficientScope = 'insufficient_scope',
  InvalidGrant = 'invalid_grant',
  InvalidClient = 'invalid_client',
  UnauthorizedClient = 'unauthorized_client',
  UnsupportedGrantType = 'unsupported_grant_type',
  InvalidScope = 'invalid_scope',

  // DPoP
  InvalidDpopProof = 'invalid_dpop_proof',
  UseDpopNonce = 'use_dpop_nonce',

  // FiPA
  RedirectToWeb = 'redirect_to_web',
  InvalidSession = 'invalid_session',
  InsufficientAuthorization = 'insufficient_authorization',

  // Oid4vci
  InvalidCredentialRequest = 'invalid_credential_request',
  CredentialRequestDenied = 'credential_request_denied',
  UnsupportedCredentialType = 'unsupported_credential_type',
  UnsupportedCredentialFormat = 'unsupported_credential_format',
  InvalidProof = 'invalid_proof',
  InvalidNonce = 'invalid_nonce',
  InvalidEncryptionParameters = 'invalid_encryption_parameters',

  // Jar
  InvalidRequestUri = 'invalid_request_uri',
  InvalidRequestObject = 'invalid_request_object',
  RequestNotSupported = 'request_not_supported',
  RequestUriNotSupported = 'request_uri_not_supported',
}

export const vOauth2ErrorResponse = v.looseObject({
  error: v.union([v.enum(Oauth2ErrorCodes), v.string()]),
  error_description: v.optional(v.string()),
  error_uri: v.optional(v.string()),
})

export type Oauth2ErrorResponse = v.InferOutput<typeof vOauth2ErrorResponse>
