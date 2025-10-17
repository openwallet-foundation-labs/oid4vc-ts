import z from 'zod'

const zVerifierAttestation = z.object({
  format: z.string(),
  data: z.record(z.string(), z.unknown()).or(z.string()),
  credential_ids: z.array(z.string()).optional(),
})

export const zVerifierAttestations = z.array(zVerifierAttestation)

export type VerifierAttestation = z.infer<typeof zVerifierAttestation>
export type VerifierAttestations = z.infer<typeof zVerifierAttestations>
