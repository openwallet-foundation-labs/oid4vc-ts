import { z } from 'zod'

export const zOpenid4vpAuthResponse = z
  .object({
    state: z.string().optional(),
    id_token: z.string().optional(),
    vp_token: z.union([z.string(), z.array(z.string()), z.record(z.string(), z.unknown())]),
    presentation_submission: z.unknown().optional(),
    refresh_token: z.string().optional(),
    token_type: z.string().optional(),
    access_token: z.string().optional(),
    expires_in: z.number().optional(),
  })
  .passthrough()
export type Openid4vpAuthResponse = z.infer<typeof zOpenid4vpAuthResponse>
