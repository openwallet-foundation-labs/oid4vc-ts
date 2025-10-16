import { zJwtHeader, zJwtPayload } from '@openid4vc/oauth2'
import { z } from 'zod'

export const zJarmHeader = z.object({ ...zJwtHeader.shape, apu: z.string().optional(), apv: z.string().optional() })
export type JarmHeader = z.infer<typeof zJarmHeader>

export const zJarmAuthorizationResponse = z
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
  .loose()

export type JarmAuthorizationResponse = z.infer<typeof zJarmAuthorizationResponse>

export const zJarmAuthorizationResponseEncryptedOnly = z
  .object({
    ...zJwtPayload.shape,
    state: z.optional(z.string()),
  })
  .loose()
export type JarmAuthorizationResponseEncryptedOnly = z.infer<typeof zJarmAuthorizationResponseEncryptedOnly>
