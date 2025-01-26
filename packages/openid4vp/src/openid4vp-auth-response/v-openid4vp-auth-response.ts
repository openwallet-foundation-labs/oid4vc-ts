import * as v from 'valibot'

export const vOpenid4vpAuthResponse = v.looseObject({
  state: v.optional(v.string()),
  id_token: v.optional(v.string()),
  vp_token: v.union([v.string(), v.array(v.string()), v.record(v.string(), v.unknown())]),
  presentation_submission: v.optional(v.unknown()),
  refresh_token: v.optional(v.string()),
  token_type: v.optional(v.string()),
  access_token: v.optional(v.string()),
  expires_in: v.optional(v.number()), // todo: this hsould always be set with access_token
})
export type Openid4vpAuthResponse = v.InferOutput<typeof vOpenid4vpAuthResponse>
