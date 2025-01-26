import * as v from 'valibot'

export const vJarAsMetadata = v.object({
  request_object_signing_alg_values_supported: v.optional(v.array(v.string())),
  request_object_encryption_alg_values_supported: v.optional(v.array(v.string())),
  request_object_encryption_enc_values_supported: v.optional(v.array(v.string())),
})
export type JarAsMetadata = v.InferOutput<typeof vJarAsMetadata>
