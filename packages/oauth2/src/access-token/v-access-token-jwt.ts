import { vInteger } from '@animo-id/oid4vc-utils'
import * as v from 'valibot'
import { vJwtHeader, vJwtPayload } from '../common/jwt/v-jwt'

export const vAccessTokenProfileJwtHeader = v.looseObject({
  ...vJwtHeader.entries,
  typ: v.picklist(['application/at+jwt', 'at+jwt']),
})
export type AccessTokenProfileJwtHeader = v.InferOutput<typeof vAccessTokenProfileJwtHeader>

export const vAccessTokenProfileJwtPayload = v.looseObject({
  ...vJwtPayload.entries,
  iss: v.string(),
  exp: vInteger,
  iat: vInteger,
  aud: v.string(),
  sub: v.string(),

  // REQUIRED according to RFC 9068, but OID4VCI allows anonymous access
  client_id: v.optional(v.string()),
  jti: v.string(),

  // SHOULD be included in the authorization request contained it
  scope: v.optional(v.string()),
})
export type AccessTokenProfileJwtPayload = v.InferOutput<typeof vAccessTokenProfileJwtPayload>
