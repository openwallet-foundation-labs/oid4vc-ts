import { vInteger } from '@animo-id/oid4vc-utils'
import * as v from 'valibot'
import { type Jwk, vJwk } from '../jwk/v-jwk'
import { vAlgValueNotNone } from '../v-common'

export type JwtSignerDid = {
  method: 'did'
  didUrl: string
  alg: string
}

export type JwtSignerJwk = {
  method: 'jwk'
  publicJwk: Jwk
  alg: string
}

export type JwtSignerX5c = {
  method: 'x5c'
  x5c: string[]
  alg: string
}

// In case of custom nothing will be added to the header
export type JwtSignerCustom = {
  method: 'custom'
  alg: string
}

export type JwtSigner = JwtSignerDid | JwtSignerJwk | JwtSignerX5c | JwtSignerCustom

// TODO: make more strict
export const vCompactJwt = v.string()

export const vJwtConfirmationPayload = v.looseObject({
  // RFC9449. jwk thumbprint of the dpop public key to which the access token is bound
  jkt: v.optional(v.string()),
})

export const vJwtPayload = v.looseObject({
  iss: v.optional(v.string()),
  aud: v.optional(v.string()),
  iat: v.optional(vInteger),
  exp: v.optional(vInteger),
  nbf: v.optional(vInteger),
  nonce: v.optional(v.string()),
  jti: v.optional(v.string()),

  cnf: v.optional(vJwtConfirmationPayload),
})
export type JwtPayload = v.InferOutput<typeof vJwtPayload>

export const vJwtHeader = v.looseObject({
  alg: vAlgValueNotNone,
  typ: v.optional(v.string()),

  kid: v.optional(v.string()),
  jwk: v.optional(vJwk),
  x5c: v.optional(v.array(v.string())),
  trust_chain: v.optional(v.array(v.string())),
})
export type JwtHeader = v.InferOutput<typeof vJwtHeader>
