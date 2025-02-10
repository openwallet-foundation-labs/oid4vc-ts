import { Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { zHttpsUrl } from '@openid4vc/utils'
import { z } from 'zod'

export const zJarAuthRequest = z
  .object({
    request: z.optional(z.string()),
    request_uri: z.optional(zHttpsUrl),
    request_uri_method: z.optional(z.union([z.literal('GET'), z.literal('POST')])),
    client_id: z.string(),
  })
  .passthrough()
export type JarAuthRequest = z.infer<typeof zJarAuthRequest>

export function validateJarRequestParams(options: { jarRequestParams: JarAuthRequest }) {
  const { jarRequestParams } = options

  if (jarRequestParams.request && jarRequestParams.request_uri) {
    throw new Oauth2ServerErrorResponseError({
      error: 'invalid_request_object',
      error_description: 'request and request_uri cannot both be present in a JAR request',
    })
  }

  if (!jarRequestParams.request && !jarRequestParams.request_uri) {
    throw new Oauth2ServerErrorResponseError({
      error: 'invalid_request_object',
      error_description: 'request or request_uri must be present',
    })
  }

  return jarRequestParams as JarAuthRequest &
    ({ request_uri: string; request?: never } | { request: string; request_uri?: never })
}
