import { z } from 'zod'

const zVpTokenPexEntry = z.union([z.string(), z.record(z.any())], {
  message: 'pex vp_token entry must be a string or object',
})

export const zVpTokenPex = z.union(
  [zVpTokenPexEntry, z.array(zVpTokenPexEntry).nonempty('Must have at least entry in vp_token array')],
  {
    message: 'pex vp_token must be a string, object or array of strings and objects',
  }
)
export type VpTokenPex = z.infer<typeof zVpTokenPex>
export type VpTokenPexEntry = z.infer<typeof zVpTokenPexEntry>

export const zVpTokenDcql = z.record(z.union([z.string(), z.record(z.any())]), {
  message:
    'dcql vp_token must be an object with keys referencing the dcql credential query id, and values the encoded (string or object) presentation',
})
export type VpTokenDcql = z.infer<typeof zVpTokenDcql>

export const zVpToken = zVpTokenDcql.or(zVpTokenPex)
export type VpToken = z.infer<typeof zVpToken>
