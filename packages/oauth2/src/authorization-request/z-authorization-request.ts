import { zHttpsUrl, zStringToJson } from '@openid4vc/utils'
import z from 'zod'
import { zAuthorizationDetailsEntryBase } from '../common/z-authorization-details'
import { zOauth2ErrorResponse } from '../common/z-oauth2-error'

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
    authorization_details: z.array(zAuthorizationDetailsEntryBase).optional(),

    // DPoP jwk thumbprint
    dpop_jkt: z.optional(z.base64url()),

    code_challenge: z.optional(z.string()),
    code_challenge_method: z.optional(z.string()),
  })
  .loose()
export type AuthorizationRequest = z.infer<typeof zAuthorizationRequest>

// We need to parse serialized JSON to an JSON object.
export const zAuthorizationRequestParsedUriParamsToJson = z.looseObject({
  authorization_details: zStringToJson.optional(),
})

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
