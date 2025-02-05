import { z } from 'zod'
export const zVpFormatsSupported = z.record(
  z.string(),
  z.object({
    alg_values_supported: z.optional(z.array(z.string())),
  })
)

export type VpFormatsSupported = z.infer<typeof zVpFormatsSupported>
