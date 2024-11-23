import { vJwk } from '@animo-id/oauth2'
import type { InferOutputUnion, Simplify } from '@animo-id/oauth2-utils'
import * as v from 'valibot'
import {
  type ProofTypeIdentifier,
  vAttestationProofTypeIdentifier,
  vCredentialRequestProofAttestation,
  vCredentialRequestProofJwt,
  vJwtProofTypeIdentifier,
} from '../formats/proof-type'

const vCredentialRequestProofCommon = v.looseObject({
  proof_type: v.string(),
})

export const allCredentialRequestProofs = [vCredentialRequestProofJwt, vCredentialRequestProofAttestation] as const
const allCredentialRequestProofsTypes = allCredentialRequestProofs.map((format) => format.entries.proof_type.literal)

export const vCredentialRequestProof = v.intersect([
  vCredentialRequestProofCommon,
  v.variant('proof_type', [
    ...allCredentialRequestProofs,

    // To handle unrecognized proof_type values and not error immediately we allow the common format as well
    // but they can't use any of the proof_type identifiers already registered. This way if a proof_type is
    // recognized it NEEDS to use the proof_type specific validation, and otherwise we fall back to the common validation
    v.looseObject({
      proof_type: v.pipe(
        v.string(),
        v.check((input) => !allCredentialRequestProofsTypes.includes(input as ProofTypeIdentifier))
      ),
    }),
  ]),
])

const vCredentialRequestProofsCommon = v.record(v.string(), v.array(v.unknown()))
export const vCredentialRequestProofs = v.object({
  [vJwtProofTypeIdentifier.literal]: v.optional(v.array(vCredentialRequestProofJwt.entries.jwt)),
  [vAttestationProofTypeIdentifier.literal]: v.optional(
    v.array(vCredentialRequestProofAttestation.entries.attestation)
  ),
})

type CredentialRequestProofCommon = v.InferOutput<typeof vCredentialRequestProofCommon>
export type CredentialRequestProofFormatSpecific = InferOutputUnion<typeof allCredentialRequestProofs>
export type CredentialRequestProofWithFormats = Simplify<
  CredentialRequestProofCommon & CredentialRequestProofFormatSpecific
>
export type CredentialRequestProof = v.InferOutput<typeof vCredentialRequestProof>

export type CredentialRequestProofsCommon = v.InferOutput<typeof vCredentialRequestProofsCommon>
export type CredentialRequestProofsFormatSpecific = v.InferOutput<typeof vCredentialRequestProofs>
export type CredentialRequestProofsWithFormat = CredentialRequestProofsCommon & CredentialRequestProofsFormatSpecific
export type CredentialRequestProofs = v.InferOutput<typeof vCredentialRequestProofs>

export const vCredentialRequestCommon = v.pipe(
  v.looseObject({
    proof: v.optional(vCredentialRequestProof),
    proofs: v.optional(
      v.pipe(
        v.intersect([vCredentialRequestProofsCommon, vCredentialRequestProofs]), // Only one proof type allowed per requet
        v.check(
          (proofs) => Object.values(proofs).length === 1,
          `The 'proofs' object in a credential request should contain exactly one attribute`
        )
      )
    ),

    credential_response_encryption: v.optional(
      v.looseObject({
        jwk: vJwk,
        alg: v.string(),
        enc: v.string(),
      })
    ),
  }),
  // It's not allowed to provide both proof and proofs
  v.check(
    ({ proof, proofs }) => !(proof !== undefined && proofs !== undefined),
    `Both 'proof' and 'proofs' are defined. Only one is allowed`
  )
)
