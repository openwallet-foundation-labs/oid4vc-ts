import { ContentType, createZodFetcher, objectToQueryParams, parseWithErrorHandling } from '@openid4vc/utils'
import { InvalidFetchResponseError } from '@openid4vc/utils'
import { Oauth2Error } from '../error/Oauth2Error'
import type { AuthorizationServerMetadata } from '../metadata/authorization-server/z-authorization-server-metadata'

import { Headers } from '@openid4vc/utils'
import type { CallbackContext } from '../callbacks'
import {
  type TokenIntrospectionRequest,
  zTokenIntrospectionRequest,
  zTokenIntrospectionResponse,
} from './z-token-introspection'

export interface IntrospectTokenOptions {
  /**
   * Metadata of the authorization server. Must contain an `introspection_endpoint`
   */
  authorizationServerMetadata: AuthorizationServerMetadata

  /**
   * The provided acccess token
   */
  token: string

  /**
   * The scheme of the access token, will be sent along with the token
   * as a hint.
   */
  tokenTypeHint?: string

  /**
   * Additional payload to include in the introspection equest. Items will be encoded and sent
   * using x-www-form-urlencoded format. Nested items (JSON) will be stringified and url encoded.
   */
  additionalPayload?: Record<string, unknown>

  callbacks: Pick<CallbackContext, 'fetch' | 'clientAuthentication'>
}

export async function introspectToken(options: IntrospectTokenOptions) {
  const fetchWithZod = createZodFetcher(options.callbacks.fetch)

  const introspectionRequest = parseWithErrorHandling(zTokenIntrospectionRequest, {
    token: options.token,
    token_type_hint: options.tokenTypeHint,
    ...options.additionalPayload,
  } satisfies TokenIntrospectionRequest)

  const introspectionEndpoint = options.authorizationServerMetadata.introspection_endpoint
  if (!introspectionEndpoint) {
    throw new Oauth2Error(`Missing required 'introspection_endpoint' parameter in authorization server metadata`)
  }

  const headers = new Headers({
    'Content-Type': ContentType.XWwwFormUrlencoded,
  })

  // Apply client authentication
  await options.callbacks.clientAuthentication({
    url: introspectionEndpoint,
    method: 'POST',
    authorizationServerMetadata: options.authorizationServerMetadata,
    body: introspectionRequest,
    contentType: ContentType.XWwwFormUrlencoded,
    headers,
  })

  const { result, response } = await fetchWithZod(
    zTokenIntrospectionResponse,
    ContentType.Json,
    introspectionEndpoint,
    {
      body: objectToQueryParams(introspectionRequest).toString(),
      method: 'POST',
      headers,
    }
  )

  // TODO: better error handling (error response?)
  if (!response.ok || !result?.success) {
    throw new InvalidFetchResponseError(
      `Unable to introspect token from '${introspectionEndpoint}'. Received response with status ${response.status}`,
      await response.clone().text(),
      response
    )
  }

  return result.data
}
