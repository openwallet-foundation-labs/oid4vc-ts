import { zHttpsUrl } from '@openid4vc/utils'
import z from 'zod'
import { zOauth2ErrorResponse } from '../common/z-oauth2-error'

export const zPushedAuthorizationRequestUriPrefix = z.literal('urn:ietf:params:oauth:request_uri:')
export const pushedAuthorizationRequestUriPrefix = zPushedAuthorizationRequestUriPrefix.value
export type PushedAuthorizationRequestUriPrefix = z.infer<typeof zPushedAuthorizationRequestUriPrefix>

// TODO: should create different request validations for different
// response types. Currently we basically only support `code`
export const zAuthorizationRequest = z
  .object({
    response_type: z.string(),
    client_id: z.string(),

    issuer_state: z.optional(z.string()),
    redirect_uri: z.url().optional(),
    resource: z.optional(zHttpsUrl),
    scope: z.optional(z.string()),
    state: z.optional(z.string()),

    // DPoP jwk thumbprint
    dpop_jkt: z.optional(z.base64url()),

    code_challenge: z.optional(z.string()),
    code_challenge_method: z.optional(z.string()),
  })
  .loose()
export type AuthorizationRequest = z.infer<typeof zAuthorizationRequest>

export const zPushedAuthorizationRequest = z
  .object({
    request_uri: z.string(),
    client_id: z.string(),
  })
  .loose()
export type PushedAuthorizationRequest = z.infer<typeof zPushedAuthorizationRequest>

export const zPushedAuthorizationResponse = z
  .object({
    request_uri: z.string(),
    expires_in: z.number().int(),
  })
  .loose()
export type PushedAuthorizationResponse = z.infer<typeof zPushedAuthorizationResponse>

export const zPushedAuthorizationErrorResponse = zOauth2ErrorResponse
export type PushedAuthorizationErrorResponse = z.infer<typeof zPushedAuthorizationErrorResponse>
