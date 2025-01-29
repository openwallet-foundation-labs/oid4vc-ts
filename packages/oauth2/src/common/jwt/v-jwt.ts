import { vInteger } from '@openid4vc/utils'
import { type Jwk, vJwk } from '../jwk/v-jwk'
import { vAlgValueNotNone } from '../v-common'
import z from 'zod'

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

export type JwtSignerTrustChain = {
  method: 'trustChain'
  trustChain: string[]
  alg: string
  kid: string
}

// In case of custom nothing will be added to the header
export type JwtSignerCustom = {
  method: 'custom'
  alg: string
}

export type JwtSigner = JwtSignerDid | JwtSignerJwk | JwtSignerX5c | JwtSignerTrustChain | JwtSignerCustom

export type JwtSignerWithJwk = JwtSigner & { publicJwk: Jwk }

export const vCompactJwt = z.string().regex(/^([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_\-\+\/=]*)$/, {
  message: 'Not a valid compact jwt',
})

export const vJwtConfirmationPayload = z
  .object({
    jwk: vJwk.optional(),

    // RFC9449. jwk thumbprint of the dpop public key to which the access token is bound
    jkt: z.string().optional(),
  })
  .passthrough()

export const vJwtPayload = z
  .object({
    iss: z.string().optional(),
    aud: z.string().optional(),
    iat: vInteger.optional(),
    exp: vInteger.optional(),
    nbf: vInteger.optional(),
    nonce: z.string().optional(),
    jti: z.string().optional(),

    cnf: vJwtConfirmationPayload.optional(),

    // Reserved for status parameters
    status: z.record(z.string(), z.any()).optional(),
  })
  .passthrough()

export type JwtPayload = z.infer<typeof vJwtPayload>

export const vJwtHeader = z
  .object({
    alg: vAlgValueNotNone,
    typ: z.string().optional(),

    kid: z.string().optional(),
    jwk: vJwk.optional(),
    x5c: z.array(z.string()).optional(),
    trust_chain: z.array(z.string()).optional(),
  })
  .passthrough()

export type JwtHeader = z.infer<typeof vJwtHeader>
