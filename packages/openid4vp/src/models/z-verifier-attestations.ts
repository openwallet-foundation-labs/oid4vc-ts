import z from 'zod'

const zVerifierAttestation = z.object({
  format: z.string(),
  data: z.record(z.unknown()).or(z.string()),
  credential_ids: z.array(z.string()).optional(),
})

export const zVerifierAttestations = z.array(zVerifierAttestation)

export type VerfierAttestation = z.infer<typeof zVerifierAttestation>
export type VerfierAttestations = z.infer<typeof zVerifierAttestations>
