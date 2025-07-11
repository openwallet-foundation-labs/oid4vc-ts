import { z } from 'zod'

const zVpTokenPresentationEntry = z.union([z.string(), z.record(z.any())], {
  message: 'vp_token presentation entry must be string or object',
})
export type VpTokenPresentationEntry = z.infer<typeof zVpTokenPresentationEntry>

export const zVpTokenPex = z.union(
  [
    zVpTokenPresentationEntry,
    z.array(zVpTokenPresentationEntry).nonempty('Must have at least entry in vp_token array'),
  ],
  {
    message: 'pex vp_token must be a string, object or non-empty array of strings and objects',
  }
)
export type VpTokenPex = z.infer<typeof zVpTokenPex>

export const zVpTokenDcql = z.record(
  z.union([z.array(zVpTokenPresentationEntry).nonempty(), zVpTokenPresentationEntry]),
  {
    message:
      'dcql vp_token must be an object with keys referencing the dcql credential query id, and values a non-empty array of strings and objects, or string, or object',
  }
)
export type VpTokenDcql = z.infer<typeof zVpTokenDcql>

export const zVpToken = zVpTokenDcql.or(zVpTokenPex)
export type VpToken = z.infer<typeof zVpToken>
