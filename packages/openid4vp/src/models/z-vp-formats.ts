import { z } from 'zod'

export const zVpFormats = z.optional(z.record(z.string(), z.unknown()))
export type VpFormats = z.infer<typeof zVpFormats>
