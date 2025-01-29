import { vInteger } from '@openid4vc/utils'
import z from 'zod'
import { vJwtConfirmationPayload } from '../common/jwt/v-jwt'

export const vTokenIntrospectionRequest = z
  .object({
    token: z.string(),
    token_type_hint: z.optional(z.string()),
  })
  .passthrough()

export type TokenIntrospectionRequest = z.infer<typeof vTokenIntrospectionRequest>

export const vTokenIntrospectionResponse = z
  .object({
    active: z.boolean(),
    scope: z.optional(z.string()),
    client_id: z.optional(z.string()),
    username: z.optional(z.string()),
    token_type: z.optional(z.string()),

    exp: z.optional(vInteger),
    iat: z.optional(vInteger),
    nbf: z.optional(vInteger),

    sub: z.optional(z.string()),
    aud: z.optional(z.string()),

    iss: z.optional(z.string()),
    jti: z.optional(z.string()),

    cnf: z.optional(vJwtConfirmationPayload),
  })
  .passthrough()

export type TokenIntrospectionResponse = z.infer<typeof vTokenIntrospectionResponse>
