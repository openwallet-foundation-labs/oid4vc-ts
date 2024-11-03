import * as v from 'valibot'

export enum Oauth2ErrorCodes {
  InvalidRequest = 'invalid_request',
  InvalidToken = 'invalid_token',
  InsufficientScope = 'insufficient_scope',
  InvalidDpopProof = 'invalid_dpop_proof',
  UseDpopNonce = 'use_dpop_nonce',
  InvalidGrant = 'invalid_grant',
}

export const vOauth2ErrorResponse = v.looseObject({
  error: v.union([v.enum(Oauth2ErrorCodes), v.string()]),
  error_description: v.optional(v.string()),
})

export type Oauth2ErrorResponse = v.InferOutput<typeof vOauth2ErrorResponse>
