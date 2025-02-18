import z from 'zod'

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

  // OpenId4Vp
  VpFormatsNotSupported = 'vp_formats_not_supported',
  AccessDenied = 'access_denied',
  InvalidPresentationDefinitionUri = 'invalid_presentation_definition_uri',
  InvalidPresentationDefinitionReference = 'invalid_presentation_definition_reference',
  InvalidRequestUriMethod = 'invalid_request_uri_method',
  InvalidTransactionData = 'invalid_transaction_data',
  WalletUnavailable = 'wallet_unavailable',
}

export const zOauth2ErrorResponse = z
  .object({
    error: z.union([z.nativeEnum(Oauth2ErrorCodes), z.string()]),
    error_description: z.string().optional(),
    error_uri: z.string().optional(),
  })
  .passthrough()

export type Oauth2ErrorResponse = z.infer<typeof zOauth2ErrorResponse>
