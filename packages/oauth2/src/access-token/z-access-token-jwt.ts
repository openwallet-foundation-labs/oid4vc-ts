import { zInteger } from '@openid4vc/utils'
import z from 'zod'
import { zJwtHeader, zJwtPayload } from '../common/jwt/z-jwt'

export const zAccessTokenProfileJwtHeader = z
  .object({
    ...zJwtHeader.shape,
    typ: z.enum(['application/at+jwt', 'at+jwt']),
  })
  .loose()
export type AccessTokenProfileJwtHeader = z.infer<typeof zAccessTokenProfileJwtHeader>

export const zAccessTokenProfileJwtPayload = z
  .object({
    ...zJwtPayload.shape,
    iss: z.string(),
    exp: zInteger,
    iat: zInteger,
    aud: z.union([z.string(), z.array(z.string())]),
    sub: z.string(),

    // REQUIRED according to RFC 9068, but OpenID4VCI allows anonymous access
    client_id: z.optional(z.string()),
    jti: z.string(),

    // SHOULD be included in the authorization request contained it
    scope: z.optional(z.string()),
  })
  .loose()

export type AccessTokenProfileJwtPayload = z.infer<typeof zAccessTokenProfileJwtPayload>
