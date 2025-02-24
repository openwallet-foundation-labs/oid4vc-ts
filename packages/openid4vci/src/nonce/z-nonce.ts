import { zInteger } from '@openid4vc/utils'
import z from 'zod'

export const zNonceResponse = z
  .object({
    c_nonce: z.string(),
    c_nonce_expires_in: z.optional(zInteger),
  })
  .passthrough()
export type NonceResponse = z.infer<typeof zNonceResponse>
