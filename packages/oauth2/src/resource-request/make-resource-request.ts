import type { FetchResponse } from '@animo-id/oid4vc-utils'
import type { CallbackContext } from '../callbacks'
import {
  type CreateDpopJwtOptions,
  type RequestDpopOptions,
  createDpopJwt,
  extractDpopNonceFromHeaders,
} from '../dpop/dpop'
import { shouldRetryResourceRequestWithDPoPNonce } from '../dpop/dpop-retry'
import { Oauth2ClientErrorResponseError } from '../error/Oauth2ClientErrorResponseError'
import { Oauth2InvalidFetchResponseError } from '../error/Oauth2InvalidFetchResponseError'

export interface ResourceRequestOptions<T> {
  /**
   * DPoP options
   */
  dpop?: RequestDpopOptions & Pick<CreateDpopJwtOptions, 'request'>

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
  resourceRequest: (options: {
    headers: Record<string, string>
  }) => Promise<{ response: FetchResponse; result: T }>
}

export async function resourceRequestWithDpopRetry<T>(options: ResourceRequestOptions<T>) {
  try {
    const dpopJwt = options.dpop
      ? await createDpopJwt({
          request: options.dpop.request,
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
      (error instanceof Oauth2InvalidFetchResponseError || error instanceof Oauth2ClientErrorResponseError)
    ) {
      const dpopRetry = shouldRetryResourceRequestWithDPoPNonce({
        responseHeaders: error.response.headers,
      })

      // Retry with the dpop nonce
      if (dpopRetry.retry) {
        const dpopJwt = options.dpop
          ? await createDpopJwt({
              request: options.dpop.request,
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
