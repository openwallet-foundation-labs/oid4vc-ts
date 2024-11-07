import { vInteger } from '@animo-id/oauth2-utils'
import * as v from 'valibot'

export const vNonceResponse = v.looseObject({
  c_nonce: v.string(),
  c_nonce_expires_in: v.optional(vInteger),
})
export type NonceResponse = v.InferOutput<typeof vNonceResponse>
