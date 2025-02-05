import { zJwtHeader, zJwtPayload } from '../common/jwt/z-jwt'

import { zHttpsUrl, zInteger } from '@openid4vc/utils'
import z from 'zod'
import { zJwk } from '../common/jwk/z-jwk'

export const zOauthClientAttestationHeader = z.literal('OAuth-Client-Attestation')
export const oauthClientAttestationHeader = zOauthClientAttestationHeader.value

export const zClientAttestationJwtPayload = z
  .object({
    ...zJwtPayload.shape,
    iss: z.string(),
    sub: z.string(),
    exp: zInteger,
    cnf: z
      .object({
        jwk: zJwk,
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
export type ClientAttestationJwtPayload = z.infer<typeof zClientAttestationJwtPayload>

export const zClientAttestationJwtHeader = z
  .object({
    ...zJwtHeader.shape,
    typ: z.literal('oauth-client-attestation+jwt'),
  })
  .passthrough()

export type ClientAttestationJwtHeader = z.infer<typeof zClientAttestationJwtHeader>

export const zOauthClientAttestationPopHeader = z.literal('OAuth-Client-Attestation-PoP')
export const oauthClientAttestationPopHeader = zOauthClientAttestationPopHeader.value

export const zClientAttestationPopJwtPayload = z
  .object({
    ...zJwtPayload.shape,
    iss: z.string(),
    exp: zInteger,
    aud: zHttpsUrl,

    jti: z.string(),
    nonce: z.optional(z.string()),
  })
  .passthrough()
export type ClientAttestationPopJwtPayload = z.infer<typeof zClientAttestationPopJwtPayload>

export const zClientAttestationPopJwtHeader = z
  .object({
    ...zJwtHeader.shape,
    typ: z.literal('oauth-client-attestation-pop+jwt'),
  })
  .passthrough()
export type ClientAttestationPopJwtHeader = z.infer<typeof zClientAttestationPopJwtHeader>
