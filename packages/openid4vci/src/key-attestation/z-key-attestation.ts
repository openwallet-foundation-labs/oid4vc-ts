import { zJwk, zJwtHeader, zJwtPayload } from '@openid4vc/oauth2'
import { zNumericDate } from '@openid4vc/utils'
import z from 'zod'

export type KeyAttestationJwtUse = 'proof_type.jwt' | 'proof_type.attestation'

export const zKeyAttestationJwtHeader = z
  .object({
    ...zJwtHeader.shape,
    typ: z
      // OpenID4VCI 1.0/1.1 final
      .literal('key-attestation+jwt')
      .or(
        // Legacy (<= draft 15) typ, accepted on verification for backwards compatibility
        z.literal('keyattestation+jwt')
      ),
  })
  .loose()
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
    iat: zNumericDate,

    attested_keys: z.array(zJwk).min(1),
    key_storage: z.optional(zIso18045OrStringArray.min(1)),
    user_authentication: z.optional(zIso18045OrStringArray.min(1)),
    certification: z.optional(z.url()),
  })
  .loose()

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
      exp: use === 'proof_type.jwt' ? zNumericDate : z.optional(zNumericDate),
    })
    .loose()

export type KeyAttestationJwtPayload = z.infer<typeof zKeyAttestationJwtPayload>
