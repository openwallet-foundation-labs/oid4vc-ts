import { zHttpsUrl, zInteger } from '@openid4vc/utils'
import z from 'zod'
import { zJwk } from '../common/jwk/z-jwk'
import { zJwtHeader, zJwtPayload } from '../common/jwt/z-jwt'

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
      })
      .loose(),

    // OID4VCI Wallet Attestation Extensions
    wallet_name: z.string().optional(),
    wallet_link: z.url().optional(),
  })
  .loose()
export type ClientAttestationJwtPayload = z.infer<typeof zClientAttestationJwtPayload>

export const zClientAttestationJwtHeader = z
  .object({
    ...zJwtHeader.shape,
    typ: z.literal('oauth-client-attestation+jwt'),
  })
  .loose()

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
  .loose()
export type ClientAttestationPopJwtPayload = z.infer<typeof zClientAttestationPopJwtPayload>

export const zClientAttestationPopJwtHeader = z
  .object({
    ...zJwtHeader.shape,
    typ: z.literal('oauth-client-attestation-pop+jwt'),
  })
  .loose()
export type ClientAttestationPopJwtHeader = z.infer<typeof zClientAttestationPopJwtHeader>
