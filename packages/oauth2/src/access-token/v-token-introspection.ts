import { vInteger } from '@animo-id/oid4vc-utils'
import * as v from 'valibot'
import { vJwtConfirmationPayload } from '../common/jwt/v-jwt'

export const vTokenIntrospectionRequest = v.looseObject({
  token: v.string(),
  token_type_hint: v.optional(v.string()),
})
export type TokenIntrospectionRequest = v.InferOutput<typeof vTokenIntrospectionRequest>

export const vTokenIntrospectionResponse = v.looseObject({
  active: v.boolean(),
  scope: v.optional(v.string()),
  client_id: v.optional(v.string()),
  username: v.optional(v.string()),
  token_type: v.optional(v.string()),

  exp: v.optional(vInteger),
  iat: v.optional(vInteger),
  nbf: v.optional(vInteger),

  sub: v.optional(v.string()),
  aud: v.optional(v.string()),

  iss: v.optional(v.string()),
  jti: v.optional(v.string()),

  cnf: v.optional(vJwtConfirmationPayload),
})

export type TokenIntrospectionResponse = v.InferOutput<typeof vTokenIntrospectionResponse>
