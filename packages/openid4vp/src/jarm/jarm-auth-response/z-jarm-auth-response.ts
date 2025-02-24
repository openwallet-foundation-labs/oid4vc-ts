import { zJwtPayload } from '@openid4vc/oauth2'
import { z } from 'zod'

export const zJarmAuthResponse = z
  .object({
    /**
     * iss: The issuer URL of the authorization server that created the response
     * aud: The client_id of the client the response is intended for
     * exp: The expiration time of the JWT. A maximum JWT lifetime of 10 minutes is RECOMMENDED.
     */
    ...zJwtPayload.shape,
    ...zJwtPayload.pick({ iss: true, aud: true, exp: true }).required().shape,
    state: z.optional(z.string()),
  })
  .passthrough()

export type JarmAuthResponse = z.infer<typeof zJarmAuthResponse>

export const zJarmAuthResponseEncryptedOnly = z
  .object({
    ...zJwtPayload.shape,
    state: z.optional(z.string()),
  })
  .passthrough()
export type JarmAuthResponseEncryptedOnly = z.infer<typeof zJarmAuthResponseEncryptedOnly>
