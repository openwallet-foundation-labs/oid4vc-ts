import * as v from 'valibot'

export enum Oauth2ErrorCodes {
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

  // FaPI
  RedirectToWeb = 'redirect_to_web',
  InvalidSession = 'invalid_session',
  InsufficientAuthorization = 'insufficient_authorization',
}

export const vOauth2ErrorResponse = v.looseObject({
  error: v.union([v.enum(Oauth2ErrorCodes), v.string()]),
  error_description: v.optional(v.string()),
  error_uri: v.optional(v.string()),
})

export type Oauth2ErrorResponse = v.InferOutput<typeof vOauth2ErrorResponse>
