import { vJwtHeader, vJwtPayload } from '../common/jwt/v-jwt'

import { vHttpsUrl, vInteger } from '@openid4vc/utils'
import { vJwk } from '../common/jwk/v-jwk'
import z from 'zod'

export const vOauthClientAttestationHeader = z.literal('OAuth-Client-Attestation')
export const oauthClientAttestationHeader = vOauthClientAttestationHeader.value

export const vClientAttestationJwtPayload = z
  .object({
    ...vJwtPayload.shape,
    iss: z.string(),
    sub: z.string(),
    exp: vInteger,
    cnf: z
      .object({
        jwk: vJwk,
        key_type: z.optional(
          z.union([
            z.enum(['software', 'hardware', 'tee', 'secure_enclave', 'strong_box', 'secure_element', 'hsm']),
            z.string(),
          ])
        ),
        user_authentication: z.optional(
          z.union([
            z.enum(['system_biometry', 'system_pin', 'internal_biometry', 'internal_pin', 'secure_element_pin']),
            z.string(),
          ])
        ),
      })
      .passthrough(),

    aal: z.optional(z.string()),
  })
  .passthrough()
export type ClientAttestationJwtPayload = z.infer<typeof vClientAttestationJwtPayload>

export const vClientAttestationJwtHeader = z
  .object({
    ...vJwtHeader.shape,
    typ: z.literal('oauth-client-attestation+jwt'),
  })
  .passthrough()

export type ClientAttestationJwtHeader = z.infer<typeof vClientAttestationJwtHeader>

export const vOauthClientAttestationPopHeader = z.literal('OAuth-Client-Attestation-PoP')
export const oauthClientAttestationPopHeader = vOauthClientAttestationPopHeader.value

export const vClientAttestationPopJwtPayload = z
  .object({
    ...vJwtPayload.shape,
    iss: z.string(),
    exp: vInteger,
    aud: vHttpsUrl,

    jti: z.string(),
    nonce: z.optional(z.string()),
  })
  .passthrough()
export type ClientAttestationPopJwtPayload = z.infer<typeof vClientAttestationPopJwtPayload>

export const vClientAttestationPopJwtHeader = z
  .object({
    ...vJwtHeader.shape,
    typ: z.literal('oauth-client-attestation-pop+jwt'),
  })
  .passthrough()
export type ClientAttestationPopJwtHeader = z.infer<typeof vClientAttestationPopJwtHeader>
