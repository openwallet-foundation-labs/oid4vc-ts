import * as v from 'valibot'

export const vJarDcrMetadata = v.object({
  request_object_signing_alg: v.optional(v.string()),
  request_object_encryption_alg: v.optional(v.string()),
  request_object_encryption_enc: v.optional(v.string()),
})
export type JarDcrMetadata = v.InferOutput<typeof vJarDcrMetadata>
