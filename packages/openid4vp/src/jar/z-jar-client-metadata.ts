import { z } from 'zod'

export const zJarDynamicClientRegistrationMetadata = z.object({
  request_object_signing_alg: z.optional(z.string()),
  request_object_encryption_alg: z.optional(z.string()),
  request_object_encryption_enc: z.optional(z.string()),
})
export type JarDynamicClientRegistrationMetadata = z.infer<typeof zJarDynamicClientRegistrationMetadata>
