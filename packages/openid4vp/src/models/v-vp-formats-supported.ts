import * as v from 'valibot'
export const vVpFormatsSupported = v.record(
  v.string(),
  v.object({
    alg_values_supported: v.optional(v.array(v.string())),
  })
)

export type VpFormatsSupported = v.InferOutput<typeof vVpFormatsSupported>
