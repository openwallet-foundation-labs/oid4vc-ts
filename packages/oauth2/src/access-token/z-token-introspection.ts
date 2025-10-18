import { zInteger } from '@openid4vc/utils'
import z from 'zod'
import { zJwtConfirmationPayload } from '../common/jwt/z-jwt'
import { zAuthorizationDetailsEntryBase } from '../common/z-authorization-details'

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

    exp: z.optional(zInteger),
    iat: z.optional(zInteger),
    nbf: z.optional(zInteger),

    sub: z.optional(z.string()),
    aud: z.optional(z.string()),

    iss: z.optional(z.string()),
    jti: z.optional(z.string()),

    cnf: z.optional(zJwtConfirmationPayload),

    // Authorization Details may be added to introspection response
    // to allow a resource server to understand the authorizations
    authorization_details: z.array(zAuthorizationDetailsEntryBase).optional(),
  })
  .loose()

export type TokenIntrospectionResponse = z.infer<typeof zTokenIntrospectionResponse>
