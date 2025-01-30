import { vJwk, vJwtHeader, vJwtPayload } from '@openid4vc/oauth2'
import { vInteger } from '@openid4vc/utils'
import z from 'zod'

export type KeyAttestationJwtUse = 'proof_type.jwt' | 'proof_type.attestation'

export const vKeyAttestationJwtHeader = z
  .object({
    ...vJwtHeader.shape,
    typ: z.literal('keyattestation+jwt'),
  })
  .passthrough()
  .refine(({ kid, jwk }) => jwk === undefined || kid === undefined, {
    message: `Both 'jwk' and 'kid' are defined. Only one is allowed`,
  })
  .refine(({ trust_chain, kid }) => !trust_chain || !kid, {
    message: `When 'trust_chain' is provided, 'kid' is required`,
  })

export type KeyAttestationJwtHeader = z.infer<typeof vKeyAttestationJwtHeader>

export const vIso18045 = z.enum(['iso_18045_high', 'iso_18045_moderate', 'iso_18045_enhanced-basic', 'iso_18045_basic'])

export type Iso18045 = z.infer<typeof vIso18045>
export const vIso18045OrStringArray = z.array(z.union([vIso18045, z.string()]))

export const vKeyAttestationJwtPayload = z
  .object({
    ...vJwtPayload.shape,
    iat: vInteger,

    attested_keys: z.array(vJwk),
    key_storage: z.optional(vIso18045OrStringArray),
    user_authentication: z.optional(vIso18045OrStringArray),
    certification: z.optional(z.string()),
  })
  .passthrough()

export const vKeyAttestationJwtPayloadForUse = <Use extends KeyAttestationJwtUse | undefined>(use?: Use) =>
  z
    .object({
      ...vKeyAttestationJwtPayload.shape,

      // REQUIRED when used as proof_type.attesation directly
      nonce:
        use === 'proof_type.attestation'
          ? z.string({
              message: `Nonce must be defined when key attestation is used as 'proof_type.attestation' directly`,
            })
          : z.optional(z.string()),

      // REQUIRED when used within header of proof_type.jwt
      exp: use === 'proof_type.jwt' ? vInteger : z.optional(vInteger),
    })
    .passthrough()

export type KeyAttestationJwtPayload = z.infer<typeof vKeyAttestationJwtPayload>
