import * as v from 'valibot'

export const vAuthorizationRequest = v.looseObject({
  response_type: v.string(),
  client_id: v.string(),

  issuer_state: v.optional(v.string()),
  redirect_uri: v.optional(v.string()),
  scope: v.optional(v.string()),

  code_challenge: v.optional(v.string()),
  code_challenge_method: v.optional(v.string()),
})
export type AuthorizationRequest = v.InferOutput<typeof vAuthorizationRequest>

export const vPushedAuthorizationRequest = v.looseObject({
  request_uri: v.string(),
  client_id: v.string(),
})
export type PushedAuthorizationRequest = v.InferOutput<typeof vPushedAuthorizationRequest>

export const vPushedAuthorizationResponse = v.looseObject({
  request_uri: v.string(),
  expires_in: v.pipe(v.number(), v.integer()),
})
export type PushedAuthorizationResponse = v.InferOutput<typeof vPushedAuthorizationResponse>
