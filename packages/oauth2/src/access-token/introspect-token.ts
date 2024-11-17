import { ContentType, createValibotFetcher, objectToQueryParams, parseWithErrorHandling } from '@animo-id/oauth2-utils'
import { InvalidFetchResponseError } from '@animo-id/oauth2-utils'
import { Oauth2Error } from '../error/Oauth2Error'
import type { AuthorizationServerMetadata } from '../metadata/authorization-server/v-authorization-server-metadata'

import { Headers } from '@animo-id/oauth2-utils'
import type { CallbackContext } from '../callbacks'
import {
  type TokenIntrospectionRequest,
  vTokenIntrospectionRequest,
  vTokenIntrospectionResponse,
} from './v-token-introspection'

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
  const fetchWithValibot = createValibotFetcher(options.callbacks.fetch)

  const introspectionRequest = parseWithErrorHandling(vTokenIntrospectionRequest, {
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
    authorizationServerMetata: options.authorizationServerMetadata,
    body: introspectionRequest,
    contentType: ContentType.XWwwFormUrlencoded,
    headers,
  })

  const { result, response } = await fetchWithValibot(
    vTokenIntrospectionResponse,
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

  return result.output
}
