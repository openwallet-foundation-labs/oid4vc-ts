import { zInteger } from '@openid4vc/utils'

import z from 'zod'
import { zAuthorizationRequest } from '../authorization-request/z-authorization-request'
import { zOauth2ErrorResponse } from '../common/z-oauth2-error'

export const zAuthorizationChallengeRequest = z
  .object({
    // authorization challenge request can include same parameters as an authorization request
    // except for response_type (always `code`), and `client_id` is optional (becase
    // it's possible to do client authentication using different methods)
    ...zAuthorizationRequest.omit({ response_type: true, client_id: true }).shape,
    client_id: z.optional(zAuthorizationRequest.shape.client_id),

    auth_session: z.optional(z.string()),

    // DRAFT presentation during issuance
    presentation_during_issuance_session: z.optional(z.string()),
  })
  .loose()
export type AuthorizationChallengeRequest = z.infer<typeof zAuthorizationChallengeRequest>

export const zAuthorizationChallengeResponse = z
  .object({
    authorization_code: z.string(),
  })
  .loose()
export type AuthorizationChallengeResponse = z.infer<typeof zAuthorizationChallengeResponse>

export const zAuthorizationChallengeErrorResponse = z
  .object({
    ...zOauth2ErrorResponse.shape,
    auth_session: z.optional(z.string()),
    request_uri: z.optional(z.string()),
    expires_in: z.optional(zInteger),

    // DRAFT: presentation during issuance
    presentation: z.optional(z.string()),
  })
  .loose()
export type AuthorizationChallengeErrorResponse = z.infer<typeof zAuthorizationChallengeErrorResponse>
