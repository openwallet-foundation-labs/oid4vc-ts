import { vInteger } from '@openid4vc/utils'

import { vAuthorizationRequest } from '../authorization-request/v-authorization-request'
import { vOauth2ErrorResponse } from '../common/v-oauth2-error'
import z from 'zod'

export const vAuthorizationChallengeRequest = z
  .object({
    // authorization challenge request can include same parameters as an authorization request
    // except for response_type (always `code`), and `client_id` is optional (becase
    // it's possible to do client authentication using different methods)
    ...vAuthorizationRequest.omit({ response_type: true, client_id: true }).shape,
    client_id: z.optional(vAuthorizationRequest.shape.client_id),

    auth_session: z.optional(z.string()),

    // DRAFT presentation during issuance
    presentation_during_issuance_session: z.optional(z.string()),
  })
  .passthrough()
export type AuthorizationChallengeRequest = z.infer<typeof vAuthorizationChallengeRequest>

export const vAuthorizationChallengeResponse = z
  .object({
    authorization_code: z.string(),
  })
  .passthrough()
export type AuthorizationChallengeResponse = z.infer<typeof vAuthorizationChallengeResponse>

export const vAuthorizationChallengeErrorResponse = z
  .object({
    ...vOauth2ErrorResponse.shape,
    auth_session: z.optional(z.string()),
    request_uri: z.optional(z.string()),
    expires_in: z.optional(vInteger),

    // DRAFT: presentation during issuance
    presentation: z.optional(z.string()),
  })
  .passthrough()
export type AuthorizationChallengeErrorResponse = z.infer<typeof vAuthorizationChallengeErrorResponse>
