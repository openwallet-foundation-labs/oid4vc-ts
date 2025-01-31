import { vInteger } from '@openid4vc/utils'
import z from 'zod'
import { vJwtHeader, vJwtPayload } from '../common/jwt/v-jwt'

export const vAccessTokenProfileJwtHeader = z
  .object({
    ...vJwtHeader.shape,
    typ: z.enum(['application/at+jwt', 'at+jwt']),
  })
  .passthrough()
export type AccessTokenProfileJwtHeader = z.infer<typeof vAccessTokenProfileJwtHeader>

export const vAccessTokenProfileJwtPayload = z
  .object({
    ...vJwtPayload.shape,
    iss: z.string(),
    exp: vInteger,
    iat: vInteger,
    aud: z.string(),
    sub: z.string(),

    // REQUIRED according to RFC 9068, but OID4VCI allows anonymous access
    client_id: z.optional(z.string()),
    jti: z.string(),

    // SHOULD be included in the authorization request contained it
    scope: z.optional(z.string()),
  })
  .passthrough()

export type AccessTokenProfileJwtPayload = z.infer<typeof vAccessTokenProfileJwtPayload>
