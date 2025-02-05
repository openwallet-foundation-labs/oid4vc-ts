import { zJwk } from '@openid4vc/oauth2'
import type { InferOutputUnion, Simplify } from '@openid4vc/utils'
import z from 'zod'
import {
  zAttestationProofTypeIdentifier,
  zCredentialRequestProofAttestation,
  zCredentialRequestProofJwt,
  zJwtProofTypeIdentifier,
} from '../formats/proof-type'

const zCredentialRequestProofCommon = z
  .object({
    proof_type: z.string(),
  })
  .passthrough()

export const allCredentialRequestProofs = [zCredentialRequestProofJwt, zCredentialRequestProofAttestation] as const

export const zCredentialRequestProof = z.union([
  zCredentialRequestProofCommon,
  z.discriminatedUnion('proof_type', allCredentialRequestProofs),
])

const zCredentialRequestProofsCommon = z.record(z.string(), z.array(z.unknown()))
export const zCredentialRequestProofs = z.object({
  [zJwtProofTypeIdentifier.value]: z.optional(z.array(zCredentialRequestProofJwt.shape.jwt)),
  [zAttestationProofTypeIdentifier.value]: z.optional(z.array(zCredentialRequestProofAttestation.shape.attestation)),
})

type CredentialRequestProofCommon = z.infer<typeof zCredentialRequestProofCommon>
export type CredentialRequestProofFormatSpecific = InferOutputUnion<typeof allCredentialRequestProofs>
export type CredentialRequestProofWithFormats = Simplify<
  CredentialRequestProofCommon & CredentialRequestProofFormatSpecific
>
export type CredentialRequestProof = z.infer<typeof zCredentialRequestProof>

export type CredentialRequestProofsCommon = z.infer<typeof zCredentialRequestProofsCommon>
export type CredentialRequestProofsFormatSpecific = z.infer<typeof zCredentialRequestProofs>
export type CredentialRequestProofsWithFormat = CredentialRequestProofsCommon & CredentialRequestProofsFormatSpecific
export type CredentialRequestProofs = z.infer<typeof zCredentialRequestProofs>

export const zCredentialRequestCommon = z
  .object({
    proof: zCredentialRequestProof.optional(),
    proofs: z.optional(
      z
        .intersection(zCredentialRequestProofsCommon, zCredentialRequestProofs)
        .refine((proofs) => Object.values(proofs).length === 1, {
          message: `The 'proofs' object in a credential request should contain exactly one attribute`,
        })
    ),

    credential_response_encryption: z
      .object({
        jwk: zJwk,
        alg: z.string(),
        enc: z.string(),
      })
      .passthrough()
      .optional(),
  })
  .passthrough()
  // It's not allowed to provide both proof and proofs
  .refine(({ proof, proofs }) => !(proof !== undefined && proofs !== undefined), {
    message: `Both 'proof' and 'proofs' are defined. Only one is allowed`,
  })
