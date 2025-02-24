import { z } from 'zod'

export const zVpToken = z.union([
  z.string(),
  z.array(z.union([z.string(), z.record(z.any())])),
  z.record(z.string(), z.unknown()),
])
export type VpToken = z.infer<typeof zVpToken>
