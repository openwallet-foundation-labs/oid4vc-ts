import { zNumericDate } from '@openid4vc/utils'
import z from 'zod'
import { zJwtConfirmationPayload } from '../common/jwt/z-jwt'

export const zTokenIntrospectionRequest = z
  .object({
    token: z.string(),
    token_type_hint: z.optional(z.string()),
  })
  .loose()

export type TokenIntrospectionRequest = z.infer<typeof zTokenIntrospectionRequest>

export const zTokenIntrospectionResponse = z
  .object({
    active: z.boolean(),
    scope: z.optional(z.string()),
    client_id: z.optional(z.string()),
    username: z.optional(z.string()),
    token_type: z.optional(z.string()),

    exp: z.optional(zNumericDate),
    iat: z.optional(zNumericDate),
    nbf: z.optional(zNumericDate),

    sub: z.optional(z.string()),
    aud: z.optional(z.union([z.string(), z.array(z.string())])),

    iss: z.optional(z.string()),
    jti: z.optional(z.string()),

    cnf: z.optional(zJwtConfirmationPayload),
  })
  .loose()

export type TokenIntrospectionResponse = z.infer<typeof zTokenIntrospectionResponse>
