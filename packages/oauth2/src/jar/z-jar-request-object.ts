import { zJwtPayload } from '../common/jwt/z-jwt'
import { z } from 'zod'

export const zJarRequestObjectPayload = z
  .object({
    ...zJwtPayload.shape,
    client_id: z.string(),
  })
  .passthrough()
export type JarRequestObjectPayload = z.infer<typeof zJarRequestObjectPayload>


const zSignedAuthorizationRequestJwtHeaderTyp = z.literal('oauth-authz-req+jwt')
export const signedAuthorizationRequestJwtHeaderTyp = zSignedAuthorizationRequestJwtHeaderTyp.value

const zJwtAuthorizationRequestJwtHeaderTyp = z.literal('jwt')
export const jwtAuthorizationRequestJwtHeaderTyp = zJwtAuthorizationRequestJwtHeaderTyp.value