import { type FetchRequestInit, type FetchResponse, type HttpMethod, defaultFetcher } from '@animo-id/oauth2-utils'
import type { CallbackContext } from '../callbacks'
import { type RequestDpopOptions, createDpopHeadersForRequest, extractDpopNonceFromHeaders } from '../dpop/dpop'
import { shouldRetryResourceRequestWithDPoPNonce } from '../dpop/dpop-retry'
import {
  Oauth2ResourceUnauthorizedError,
  type WwwAuthenticateHeaderChallenge,
} from '../error/Oauth2ResourceUnauthorizedError'

export interface ResourceRequestOptions {
  /**
   * DPoP options
   */
  dpop?: RequestDpopOptions & {
    /**
     * Whether to retry the request if the server responds with an error indicating
     * the request should be retried with a server provided dpop nonce
     *
     * @default true
     */
    retryWithNonce?: boolean
  }

  /**
   * Callbacks
   */
  callbacks: Pick<CallbackContext, 'fetch' | 'generateRandom' | 'signJwt' | 'hash'>

  /**
   * Access token
   */
  accessToken: string

  url: string
  requestOptions: FetchRequestInit
}

interface ResourceRequestResponseBase {
  ok: boolean
  response: FetchResponse

  /**
   * If the response included a dpop nonce to be used in subsequent requests
   */
  dpop?: {
    nonce: string
  }
}

export interface ResourceRequestResponseOk extends ResourceRequestResponseBase {
  ok: true
}

export interface ResourceRequestResponseNotOk extends ResourceRequestResponseBase {
  ok: false

  /**
   * If a WWW-Authenticate was included in the headers of the response
   * they will be parsed and added here.
   */
  wwwAuthenticate?: WwwAuthenticateHeaderChallenge[]
}

export async function resourceRequest(
  options: ResourceRequestOptions
): Promise<ResourceRequestResponseOk | ResourceRequestResponseNotOk> {
  const dpopHeaders = options.dpop
    ? await createDpopHeadersForRequest({
        request: {
          url: options.url,
          // in fetch the default is GET if not provided
          method: (options.requestOptions.method as HttpMethod) ?? 'GET',
        },
        signer: options.dpop.signer,
        callbacks: options.callbacks,
        nonce: options.dpop.nonce,
        accessToken: options.accessToken,
      })
    : undefined

  const fetch = options.callbacks.fetch ?? defaultFetcher
  const response = await fetch(options.url, {
    ...options.requestOptions,
    headers: {
      ...options.requestOptions.headers,
      Authorization: `${dpopHeaders ? 'DPoP' : 'Bearer'} ${options.accessToken}`,
      ...dpopHeaders,
    },
  })

  const dpopNonce = extractDpopNonceFromHeaders(response.headers)
  if (response.ok) {
    return {
      ok: true,
      response,
      dpop: dpopNonce
        ? {
            nonce: dpopNonce,
          }
        : undefined,
    }
  }

  const wwwAuthenticateHeader = response.headers.get('WWW-Authenticate')
  const resourceUnauthorizedError = wwwAuthenticateHeader
    ? Oauth2ResourceUnauthorizedError.fromHeaderValue(wwwAuthenticateHeader)
    : undefined

  const shouldRetryWithNonce = options.dpop?.retryWithNonce ?? true
  const dpopRetry = resourceUnauthorizedError
    ? shouldRetryResourceRequestWithDPoPNonce({
        responseHeaders: response.headers,
        resourceUnauthorizedError: resourceUnauthorizedError,
      })
    : undefined

  // only retry if retryWithNonce is set
  if (shouldRetryWithNonce && dpopRetry?.retry && options.dpop) {
    return await resourceRequest({
      ...options,
      dpop: {
        ...options.dpop,
        nonce: dpopRetry.dpopNonce,
        // We'll never try multiple times (to prevent endless recursion)
        retryWithNonce: false,
      },
    })
  }

  return {
    ok: false,
    response,
    dpop: dpopNonce
      ? {
          nonce: dpopNonce,
        }
      : undefined,
    wwwAuthenticate: resourceUnauthorizedError?.wwwAuthenticateHeaders,
  }
}
