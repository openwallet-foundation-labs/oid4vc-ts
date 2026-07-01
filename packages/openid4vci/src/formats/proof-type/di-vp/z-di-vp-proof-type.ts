import z from 'zod'

export const zDiVpProofTypeIdentifier = z.literal('di_vp')
export const diVpProofTypeIdentifier = zDiVpProofTypeIdentifier.value
export type DiVpProofTypeIdentifier = z.infer<typeof zDiVpProofTypeIdentifier>

// No JSON-LD/VC/DataIntegrity schema exists in this library and it's not this library's job to
// validate that structure — that's the caller's job via its own stack. Loose passthrough is
// intentional.
export const zCredentialRequestProofDiVp = z.object({
  proof_type: zDiVpProofTypeIdentifier,
  di_vp: z.record(z.string(), z.unknown()),
})
