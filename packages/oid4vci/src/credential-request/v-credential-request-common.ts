import * as v from 'valibot'
import { vJwk } from '../common/validation/v-common'
import { vCredentialRequestProofJwt, vJwtProofTypeIdentifier } from '../formats/proof-type/jwt/v-jwt-proof-type'

const allCredentialRequestProofs = [vCredentialRequestProofJwt] as const
const allCredentialRequestProofsTypes = allCredentialRequestProofs.map(
  (format) => format.entries.proof_type.literal
) as string[]

export const vCredentialRequestProof = v.variant('proof_type', [
  ...allCredentialRequestProofs,

  // To handle unrecognized proof_type values and not error immediately we allow the common format as well
  // but they can't use any of the proof_type identifiers already registered. This way if a proof_type is
  // recognized it NEEDS to use the proof_type specific validation, and otherwise we fall back to the common validation
  v.looseObject({
    proof_type: v.pipe(
      v.string(),
      v.check((input) => !allCredentialRequestProofsTypes.includes(input))
    ),
  }),
])

const vCredentialRequestProofs = v.looseObject({
  [vJwtProofTypeIdentifier.literal]: v.optional(v.array(vCredentialRequestProofJwt.entries.jwt)),
})

export type CredentialRequestProof = v.InferOutput<typeof vCredentialRequestProof>
export type CredentialRequestProofs = v.InferOutput<typeof vCredentialRequestProofs>

export const vCredentialRequestCommon = v.pipe(
  v.looseObject({
    proof: v.optional(vCredentialRequestProof),
    proofs: v.optional(vCredentialRequestProofs),

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
  ),
  // Only one proof type allowed per requet
  v.check(
    ({ proofs }) => (proofs === undefined ? true : Object.values(proofs).length === 1),
    `The 'proofs' object in a credential request should contain exactly one attribute`
  )
)
