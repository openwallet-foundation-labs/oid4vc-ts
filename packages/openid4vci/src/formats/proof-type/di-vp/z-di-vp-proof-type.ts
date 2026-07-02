import z from 'zod'

export const zDiVpProofTypeIdentifier = z.literal('di_vp')
export const diVpProofTypeIdentifier = zDiVpProofTypeIdentifier.value
export type DiVpProofTypeIdentifier = z.infer<typeof zDiVpProofTypeIdentifier>

export const zCredentialRequestProofDiVp = z.object({
  proof_type: zDiVpProofTypeIdentifier,
  di_vp: z.record(z.string(), z.unknown()),
})

export const zDataIntegrityProof = z
  .object({
    type: z.literal('DataIntegrityProof', { message: `di_vp proof 'proof.type' must be 'DataIntegrityProof'` }),
    cryptosuite: z.string({ message: `di_vp proof is missing required 'proof.cryptosuite'` }),
    proofPurpose: z.literal('authentication', {
      message: `di_vp proof 'proof.proofPurpose' must be 'authentication'`,
    }),
    domain: z.string(),
    challenge: z.string().optional(),
    verificationMethod: z.string({ message: `di_vp proof is missing required 'proof.verificationMethod'` }),
  })
  .loose()
export type DataIntegrityProof = z.infer<typeof zDataIntegrityProof>
