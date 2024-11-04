import { vInteger } from '@animo-id/oid4vc-utils'
import * as v from 'valibot'
import { vOauth2ErrorResponse } from '../common/v-oauth2-error'

export const vAuthorizationChallengeRequest = v.looseObject({
  client_id: v.optional(v.string()),
  scope: v.optional(v.string()),
  auth_session: v.optional(v.string()),

  // PKCE
  code_challenge: v.optional(v.string()),
  code_challenge_method: v.optional(v.string()),

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
