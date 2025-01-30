import { vCompactJwt, vJwtHeader, vJwtPayload } from '@openid4vc/oauth2'
import { vHttpsUrl, vInteger } from '@openid4vc/utils'
import z from 'zod'

export const vJwtProofTypeIdentifier = z.literal('jwt')
export const jwtProofTypeIdentifier = vJwtProofTypeIdentifier.value
export type JwtProofTypeIdentifier = z.infer<typeof vJwtProofTypeIdentifier>

export const vCredentialRequestProofJwt = z.object({
  proof_type: vJwtProofTypeIdentifier,
  jwt: vCompactJwt,
})

export const vCredentialRequestJwtProofTypeHeader = vJwtHeader
  .merge(
    z.object({
      key_attestation: z.optional(vCompactJwt),
      typ: z.literal('openid4vci-proof+jwt'),
    })
  )
  .passthrough()
  .refine(({ kid, jwk }) => jwk === undefined || kid === undefined, {
    message: `Both 'jwk' and 'kid' are defined. Only one is allowed`,
  })
  .refine(({ trust_chain, kid }) => !trust_chain || !kid, {
    message: `When 'trust_chain' is provided, 'kid' is required`,
  })

export type CredentialRequestJwtProofTypeHeader = z.infer<typeof vCredentialRequestJwtProofTypeHeader>

export const vCredentialRequestJwtProofTypePayload = z
  .object({
    ...vJwtPayload.shape,
    aud: vHttpsUrl,
    iat: vInteger,
  })
  .passthrough()

export type CredentialRequestJwtProofTypePayload = z.infer<typeof vCredentialRequestJwtProofTypePayload>
