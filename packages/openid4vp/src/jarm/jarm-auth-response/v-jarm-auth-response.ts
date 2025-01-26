import { vJwtPayload } from '@openid4vc/oauth2'
import * as v from 'valibot'

export const vJarmAuthResponse = v.looseObject({
  /**
   * iss: The issuer URL of the authorization server that created the response
   * aud: The client_id of the client the response is intended for
   * exp: The expiration time of the JWT. A maximum JWT lifetime of 10 minutes is RECOMMENDED.
   */
  ...v.required(vJwtPayload, ['iss', 'aud', 'exp']).entries,
  state: v.optional(v.string()),
})

export type JarmAuthResponse = v.InferInput<typeof vJarmAuthResponse>

export const vJarmAuthResponseEncryptedOnly = v.looseObject({
  ...vJwtPayload.entries,
  state: v.optional(v.string()),
})

export type JarmAuthResponseEncryptedOnly = v.InferInput<typeof vJarmAuthResponseEncryptedOnly>
