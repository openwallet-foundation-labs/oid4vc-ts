import { vInteger } from '@animo-id/oauth2-utils'
import * as v from 'valibot'
import { vAuthorizationRequest } from '../authorization-request/v-authorization-request'
import { vOauth2ErrorResponse } from '../common/v-oauth2-error'

export const vAuthorizationChallengeRequest = v.looseObject({
  // authorization challenge request can include same parameters as an authorization request
  // except for response_type (always `code`), and `client_id` is optional (becase
  // it's possible to do client authentication using different methods)
  ...v.omit(vAuthorizationRequest, ['response_type', 'client_id']).entries,
  client_id: v.optional(vAuthorizationRequest.entries.client_id),

  auth_session: v.optional(v.string()),

  // DRAFT presentation during issuance
  presentation_during_issuance_session: v.optional(v.string()),
})
export type AuthorizationChallengeRequest = v.InferOutput<typeof vAuthorizationChallengeRequest>

export const vAuthorizationChallengeResponse = v.looseObject({
  authorization_code: v.string(),
})
export type AuthorizationChallengeResponse = v.InferOutput<typeof vAuthorizationChallengeResponse>

export const vAuthorizationChallengeErrorResponse = v.looseObject({
  ...vOauth2ErrorResponse.entries,
  auth_session: v.optional(v.string()),
  request_uri: v.optional(v.string()),
  expires_in: v.optional(vInteger),

  // DRAFT: presentation during issuance
  presentation: v.optional(v.string()),
})
export type AuthorizationChallengeErrorResponse = v.InferOutput<typeof vAuthorizationChallengeErrorResponse>
