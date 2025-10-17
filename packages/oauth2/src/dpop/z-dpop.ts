import { zHttpMethod, zHttpsUrl, zInteger } from '@openid4vc/utils'
import z from 'zod'
import { zJwk } from '../common/jwk/z-jwk'
import { zJwtHeader, zJwtPayload } from '../common/jwt/z-jwt'

export const zDpopJwtPayload = z
  .object({
    ...zJwtPayload.shape,
    iat: zInteger,
    htu: zHttpsUrl,
    htm: zHttpMethod,
    jti: z.string(),

    // Only required when presenting in combination with access token
    ath: z.optional(z.string()),
  })
  .loose()
export type DpopJwtPayload = z.infer<typeof zDpopJwtPayload>

export const zDpopJwtHeader = z
  .object({
    ...zJwtHeader.shape,
    typ: z.literal('dpop+jwt'),
    jwk: zJwk,
  })
  .loose()
export type DpopJwtHeader = z.infer<typeof zDpopJwtHeader>
