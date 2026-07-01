import { zHttpsUrl, zNumericDate } from '@openid4vc/utils'
import z from 'zod'
import { zJwk } from '../common/jwk/z-jwk'
import { zJwtHeader, zJwtPayload } from '../common/jwt/z-jwt'

export const zOauthClientAttestationHeader = z.literal('OAuth-Client-Attestation')
export const oauthClientAttestationHeader = zOauthClientAttestationHeader.value

export const zClientAttestationJwtPayload = z
  .object({
    ...zJwtPayload.shape,
    sub: z.string(),
    exp: zNumericDate,
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

// draft 09: header used by the authorization/resource server to provide a fresh challenge.
export const zOauthClientAttestationChallengeHeader = z.literal('OAuth-Client-Attestation-Challenge')
export const oauthClientAttestationChallengeHeader = zOauthClientAttestationChallengeHeader.value

export const zClientAttestationPopJwtPayload = z
  .object({
    ...zJwtPayload.shape,
    aud: z.union([zHttpsUrl, z.array(zHttpsUrl)]),

    jti: z.string(),

    // `challenge` (draft 06+) replaced `nonce`. Both are accepted on verification; `nonce`
    // is retained only for backwards compatibility with <= draft 05 PoP JWTs.
    challenge: z.optional(z.string()),
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
