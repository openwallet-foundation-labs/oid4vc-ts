import { zJwtPayload } from '@openid4vc/oauth2'
import { z } from 'zod'

export const zJarRequestObjectPayload = z
  .object({
    ...zJwtPayload.shape,
    client_id: z.string(),
  })
  .passthrough()
export type JarRequestObjectPayload = z.infer<typeof zJarRequestObjectPayload>
