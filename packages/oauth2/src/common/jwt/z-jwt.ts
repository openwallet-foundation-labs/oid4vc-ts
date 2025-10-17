import { zInteger } from '@openid4vc/utils'
import z from 'zod'
import { type Jwk, zJwk } from '../jwk/z-jwk'
import { zAlgValueNotNone } from '../z-common'

export type JwtSignerDid = {
  method: 'did'
  didUrl: string
  alg: string

  /**
   * The key id that should be used for signing. You need to make sure the kid actuall matches
   * with the key associated with the didUrl.
   */
  kid?: string
}

export type JwtSignerJwk = {
  method: 'jwk'
  publicJwk: Jwk
  alg: string

  /**
   * The key id that should be used for signing. You need to make sure the kid actuall matches
   * with the key associated with the jwk.
   *
   * If not provided the kid can also be extracted from the `publicJwk`. Providing it here means the `kid` won't
   * be included in the JWT header.
   */
  kid?: string
}

export type JwtSignerX5c = {
  method: 'x5c'
  x5c: string[]
  alg: string

  /**
   * The key id that should be used for signing. You need to make sure the kid actuall matches
   * with the key associated with the leaf certificate.
   */
  kid?: string
}

export type JwtSignerFederation = {
  method: 'federation'
  trustChain?: [string, ...string[]]
  alg: string

  /**
   * The key id that should be used for signing. You need to make sure the kid actuall matches
   * with a key present in the federation.
   */
  kid: string
}

// In case of custom nothing will be added to the header
export type JwtSignerCustom = {
  method: 'custom'
  alg: string

  /**
   * The key id that should be used for signing.
   */
  kid?: string
}

export type JwtSigner = JwtSignerDid | JwtSignerJwk | JwtSignerX5c | JwtSignerFederation | JwtSignerCustom

export type JwtSignerWithJwk = JwtSigner & { publicJwk: Jwk }

export type JweEncryptor = JwtSignerJwk & {
  enc: string

  /**
   * base64-url encoded apu
   */
  apu?: string

  /**
   * base64-url encoded apv
   */
  apv?: string
}

export const zCompactJwt = z.string().regex(/^([a-zA-Z0-9-_]+)\.([a-zA-Z0-9-_]+)\.([a-zA-Z0-9-_]+)$/, {
  message: 'Not a valid compact jwt',
})

export const zJwtConfirmationPayload = z
  .object({
    jwk: zJwk.optional(),

    // RFC9449. jwk thumbprint of the dpop public key to which the access token is bound
    jkt: z.string().optional(),
  })
  .loose()

export const zJwtPayload = z
  .object({
    iss: z.string().optional(),
    aud: z.string().optional(),
    iat: zInteger.optional(),
    exp: zInteger.optional(),
    nbf: zInteger.optional(),
    nonce: z.string().optional(),
    jti: z.string().optional(),

    cnf: zJwtConfirmationPayload.optional(),

    // Reserved for status parameters
    status: z.record(z.string(), z.any()).optional(),

    // Reserved for OpenID Federation
    trust_chain: z.tuple([z.string()], z.string()).optional(),
  })
  .loose()

export type JwtPayload = z.infer<typeof zJwtPayload>

export const zJwtHeader = z
  .object({
    alg: zAlgValueNotNone,
    typ: z.string().optional(),

    kid: z.string().optional(),
    jwk: zJwk.optional(),
    x5c: z.array(z.string()).optional(),

    // Reserved for OpenID Federation
    trust_chain: z.tuple([z.string()], z.string()).optional(),
  })
  .loose()

export type JwtHeader = z.infer<typeof zJwtHeader>
