import * as v from 'valibot'
import { vJwtHeader, vJwtPayload } from '../../common/jwt/v-jwt'
import { vHttpsUrl, vInteger, vJwk } from '../../common/validation/v-common'

export const vDpopJwtPayload = v.looseObject({
  ...vJwtPayload.entries,
  iat: vInteger,

  htu: vHttpsUrl,
  htm: v.picklist(['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT', 'PATCH']),
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
