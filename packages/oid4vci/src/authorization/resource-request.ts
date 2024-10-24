import type { CallbackContext } from '../../dist'
import { Oid4vcInvalidFetchResponseError } from '../error/Oid4vcInvalidFetchResponseError'
import { Oid4vcOauthErrorResponseError } from '../error/Oid4vcOauthErrorResponseError'
import type { FetchResponse } from '../globals'
import {
  type CreateDpopJwtOptions,
  type RequestDpopOptions,
  createDpopJwt,
  extractDpopNonceFromHeaders,
} from './dpop/dpop'
import { shouldRetryResourceRequestWithDPoPNonce } from './dpop/dpop-retry'

interface ResourceRequestOptions<T> {
  /**
   * DPoP options
   */
  dpop?: RequestDpopOptions & Pick<CreateDpopJwtOptions, 'httpMethod' | 'requestUri'>

  /**
   * Callbacks
   */
  callbacks: Pick<CallbackContext, 'fetch' | 'generateRandom' | 'signJwt' | 'hash'>

  /**
   * Access token
   */
  accessToken: string

  /**
   * The original resource request implementation.
   */
  resourceRequest: (options: { headers: Record<string, string> }) => Promise<{ response: FetchResponse; result: T }>
}

export async function resourceRequestWithDpopRetry<T>(options: ResourceRequestOptions<T>) {
  try {
    const dpopJwt = options.dpop
      ? await createDpopJwt({
          httpMethod: options.dpop.httpMethod,
          requestUri: options.dpop.requestUri,
          signer: options.dpop.signer,
          callbacks: options.callbacks,
          nonce: options.dpop.nonce,
          accessToken: options.accessToken,
        })
      : undefined

    const { response, result } = await options.resourceRequest({
      headers: {
        Authorization: `${dpopJwt ? 'DPoP' : 'Bearer'} ${options.accessToken}`,
        ...(dpopJwt ? { DPoP: dpopJwt } : {}),
      },
    })

    const dpopNonce = extractDpopNonceFromHeaders(response.headers)
    return {
      dpop: dpopNonce
        ? {
            nonce: dpopNonce,
          }
        : undefined,
      result,
    }
  } catch (error) {
    if (
      options.dpop &&
      (error instanceof Oid4vcInvalidFetchResponseError || error instanceof Oid4vcOauthErrorResponseError)
    ) {
      const dpopRetry = shouldRetryResourceRequestWithDPoPNonce({
        responseHeaders: error.response.headers,
      })

      // Retry with the dpop nonce
      if (dpopRetry.retry) {
        const dpopJwt = options.dpop
          ? await createDpopJwt({
              httpMethod: options.dpop.httpMethod,
              requestUri: options.dpop.requestUri,
              signer: options.dpop.signer,
              callbacks: options.callbacks,
              nonce: dpopRetry.dpopNonce,
              accessToken: options.accessToken,
            })
          : undefined

        const { response, result } = await options.resourceRequest({
          headers: {
            Authorization: `${dpopJwt ? 'DPoP' : 'Bearer'} ${options.accessToken}`,
            ...(dpopJwt ? { DPoP: dpopJwt } : {}),
          },
        })

        const dpopNonce = extractDpopNonceFromHeaders(response.headers)
        return {
          dpop: dpopNonce
            ? {
                nonce: dpopNonce,
              }
            : undefined,
          result,
        }
      }
    }

    throw error
  }
}
