import { z } from 'zod'
import { zVpToken } from '../vp-token/z-vp-token'

export const zOpenid4vpAuthorizationResponse = z
  .object({
    state: z.string().optional(),
    id_token: z.string().optional(),
    vp_token: zVpToken,
    presentation_submission: z.unknown().optional(),
    refresh_token: z.string().optional(),
    token_type: z.string().optional(),
    access_token: z.string().optional(),
    expires_in: z.number().optional(),
  })
  .passthrough()
export type Openid4vpAuthorizationResponse = z.infer<typeof zOpenid4vpAuthorizationResponse>
