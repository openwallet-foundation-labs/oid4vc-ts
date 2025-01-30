import { vInteger } from '@openid4vc/utils'
import z from 'zod'

export const vNonceResponse = z
  .object({
    c_nonce: z.string(),
    c_nonce_expires_in: z.optional(vInteger),
  })
  .passthrough()
export type NonceResponse = z.infer<typeof vNonceResponse>
