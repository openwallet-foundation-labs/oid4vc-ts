import { Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { vHttpsUrl } from '@openid4vc/utils'
import * as v from 'valibot'

export const vJarAuthRequest = v.object({
  request: v.optional(v.string()),
  request_uri: v.optional(vHttpsUrl),
  request_uri_method: v.optional(v.union([v.literal('GET'), v.literal('POST')])),
  client_id: v.string(),
})
export type JarAuthRequest = v.InferOutput<typeof vJarAuthRequest>

export function validateJarAuthRequest(input: { jarAuthRequest: JarAuthRequest }) {
  const { jarAuthRequest } = input

  if (jarAuthRequest.request && jarAuthRequest.request_uri) {
    throw new Oauth2ServerErrorResponseError({
      error: 'invalid_request_object',
      error_description: 'request and request_uri cannot both be present in a JAR request',
    })
  }

  if (!jarAuthRequest.request && !jarAuthRequest.request_uri) {
    throw new Oauth2ServerErrorResponseError({
      error: 'invalid_request_object',
      error_description: 'request or request_uri must be present',
    })
  }
}
