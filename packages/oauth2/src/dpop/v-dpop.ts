import * as v from 'valibot'
import { vJwtHeader, vJwtPayload } from '../common/jwt/v-jwt'

import { vHttpMethod, vHttpsUrl, vInteger } from '@openid4vc/utils'
import { vJwk } from '../common/jwk/v-jwk'

export const vDpopJwtPayload = v.looseObject({
  ...vJwtPayload.entries,
  iat: vInteger,
  htu: vHttpsUrl,
  htm: vHttpMethod,
  jti: v.string(),

  // Only required when presenting in combination with access token
  ath: v.optional(v.string()),
})
export type DpopJwtPayload = v.InferOutput<typeof vDpopJwtPayload>

export const vDpopJwtHeader = v.looseObject({
  ...vJwtHeader.entries,
  typ: v.literal('dpop+jwt'),
  jwk: vJwk,
})
export type DpopJwtHeader = v.InferOutput<typeof vDpopJwtHeader>
