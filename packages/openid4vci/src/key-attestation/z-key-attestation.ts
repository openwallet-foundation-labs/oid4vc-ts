import { zJwk, zJwtHeader, zJwtPayload } from '@openid4vc/oauth2'
import { zInteger } from '@openid4vc/utils'
import z from 'zod'

export type KeyAttestationJwtUse = 'proof_type.jwt' | 'proof_type.attestation'

export const zKeyAttestationJwtHeader = z
  .object({
    ...zJwtHeader.shape,
    typ: z
      // Draft 15
      .literal('keyattestation+jwt')
      .or(
        // Draft 16
        z.literal('key-attestation+jwt')
      ),
  })
  .passthrough()
  .refine(({ kid, jwk }) => jwk === undefined || kid === undefined, {
    message: `Both 'jwk' and 'kid' are defined. Only one is allowed`,
  })
  .refine(({ trust_chain, kid }) => !trust_chain || !kid, {
    message: `When 'trust_chain' is provided, 'kid' is required`,
  })

export type KeyAttestationJwtHeader = z.infer<typeof zKeyAttestationJwtHeader>

export const zIso18045 = z.enum(['iso_18045_high', 'iso_18045_moderate', 'iso_18045_enhanced-basic', 'iso_18045_basic'])

export type Iso18045 = z.infer<typeof zIso18045>
export const zIso18045OrStringArray = z.array(z.union([zIso18045, z.string()]))

export const zKeyAttestationJwtPayload = z
  .object({
    ...zJwtPayload.shape,
    iat: zInteger,

    attested_keys: z.array(zJwk),
    key_storage: z.optional(zIso18045OrStringArray),
    user_authentication: z.optional(zIso18045OrStringArray),
    certification: z.optional(z.string().url()),
  })
  .passthrough()

export const zKeyAttestationJwtPayloadForUse = <Use extends KeyAttestationJwtUse | undefined>(use?: Use) =>
  z
    .object({
      ...zKeyAttestationJwtPayload.shape,

      // REQUIRED when used as proof_type.attesation directly
      nonce:
        use === 'proof_type.attestation'
          ? z.string({
              message: `Nonce must be defined when key attestation is used as 'proof_type.attestation' directly`,
            })
          : z.optional(z.string()),

      // REQUIRED when used within header of proof_type.jwt
      exp: use === 'proof_type.jwt' ? zInteger : z.optional(zInteger),
    })
    .passthrough()

export type KeyAttestationJwtPayload = z.infer<typeof zKeyAttestationJwtPayload>
