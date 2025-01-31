import { vJwk } from '@openid4vc/oauth2'
import type { InferOutputUnion, Simplify } from '@openid4vc/utils'
import z from 'zod'
import {
  vAttestationProofTypeIdentifier,
  vCredentialRequestProofAttestation,
  vCredentialRequestProofJwt,
  vJwtProofTypeIdentifier,
} from '../formats/proof-type'

const vCredentialRequestProofCommon = z
  .object({
    proof_type: z.string(),
  })
  .passthrough()

export const allCredentialRequestProofs = [vCredentialRequestProofJwt, vCredentialRequestProofAttestation] as const

export const vCredentialRequestProof = z.union([
  vCredentialRequestProofCommon,
  z.discriminatedUnion('proof_type', allCredentialRequestProofs),
])

const vCredentialRequestProofsCommon = z.record(z.string(), z.array(z.unknown()))
export const vCredentialRequestProofs = z.object({
  [vJwtProofTypeIdentifier.value]: z.optional(z.array(vCredentialRequestProofJwt.shape.jwt)),
  [vAttestationProofTypeIdentifier.value]: z.optional(z.array(vCredentialRequestProofAttestation.shape.attestation)),
})

type CredentialRequestProofCommon = z.infer<typeof vCredentialRequestProofCommon>
export type CredentialRequestProofFormatSpecific = InferOutputUnion<typeof allCredentialRequestProofs>
export type CredentialRequestProofWithFormats = Simplify<
  CredentialRequestProofCommon & CredentialRequestProofFormatSpecific
>
export type CredentialRequestProof = z.infer<typeof vCredentialRequestProof>

export type CredentialRequestProofsCommon = z.infer<typeof vCredentialRequestProofsCommon>
export type CredentialRequestProofsFormatSpecific = z.infer<typeof vCredentialRequestProofs>
export type CredentialRequestProofsWithFormat = CredentialRequestProofsCommon & CredentialRequestProofsFormatSpecific
export type CredentialRequestProofs = z.infer<typeof vCredentialRequestProofs>

export const vCredentialRequestCommon = z
  .object({
    proof: vCredentialRequestProof.optional(),
    proofs: z.optional(
      z
        .intersection(vCredentialRequestProofsCommon, vCredentialRequestProofs)
        .refine((proofs) => Object.values(proofs).length === 1, {
          message: `The 'proofs' object in a credential request should contain exactly one attribute`,
        })
    ),

    credential_response_encryption: z
      .object({
        jwk: vJwk,
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
