import { vJwtPayload } from '@openid4vc/oauth2'
import * as v from 'valibot'

export const vJarRequestObjectPayload = v.looseObject({
  ...vJwtPayload.entries,
  client_id: v.string(),
})
export type JarRequestObjectPayload = v.InferOutput<typeof vJarRequestObjectPayload>
