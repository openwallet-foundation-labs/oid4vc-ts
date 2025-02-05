import { z } from 'zod'

export const zJarAsMetadata = z.object({
  request_object_signing_alg_values_supported: z.optional(z.array(z.string())),
  request_object_encryption_alg_values_supported: z.optional(z.array(z.string())),
  request_object_encryption_enc_values_supported: z.optional(z.array(z.string())),
})
export type JarAsMetadata = z.infer<typeof zJarAsMetadata>
