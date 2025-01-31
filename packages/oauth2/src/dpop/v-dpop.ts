import { vJwtHeader, vJwtPayload } from '../common/jwt/v-jwt'

import { vHttpMethod, vHttpsUrl, vInteger } from '@openid4vc/utils'
import z from 'zod'
import { vJwk } from '../common/jwk/v-jwk'

export const vDpopJwtPayload = z
  .object({
    ...vJwtPayload.shape,
    iat: vInteger,
    htu: vHttpsUrl,
    htm: vHttpMethod,
    jti: z.string(),

    // Only required when presenting in combination with access token
    ath: z.optional(z.string()),
  })
  .passthrough()
export type DpopJwtPayload = z.infer<typeof vDpopJwtPayload>

export const vDpopJwtHeader = z
  .object({
    ...vJwtHeader.shape,
    typ: z.literal('dpop+jwt'),
    jwk: vJwk,
  })
  .passthrough()
export type DpopJwtHeader = z.infer<typeof vDpopJwtHeader>
