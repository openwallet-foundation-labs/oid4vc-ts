import type { FetchHeaders } from '@openid4vc/utils'
import { SupportedAuthenticationScheme } from '../access-token/verify-access-token'
import { Oauth2ErrorCodes, type Oauth2ErrorResponse } from '../common/v-oauth2-error'
import { Oauth2ClientErrorResponseError } from '../error/Oauth2ClientErrorResponseError'
import { Oauth2Error } from '../error/Oauth2Error'
import type { Oauth2ResourceUnauthorizedError } from '../error/Oauth2ResourceUnauthorizedError'
import { type RequestDpopOptions, extractDpopNonceFromHeaders } from './dpop'

export async function authorizationServerRequestWithDpopRetry<T>(options: {
  dpop?: RequestDpopOptions
  request: (dpop?: RequestDpopOptions) => Promise<T>
}): Promise<T> {
  try {
    return await options.request(options.dpop)
  } catch (error) {
    if (options.dpop && error instanceof Oauth2ClientErrorResponseError) {
      const dpopRetry = shouldRetryAuthorizationServerRequestWithDPoPNonce({
        responseHeaders: error.response.headers,
        errorResponse: error.errorResponse,
      })

      // Retry with the dpop nonce
      if (dpopRetry.retry) {
        return options.request({
          ...options.dpop,
          nonce: dpopRetry.dpopNonce,
        })
      }
    }

    throw error
  }
}

export interface ShouldRetryAuthorizationServerRequestWithDpopNonceOptions {
  /**
   * The error response that will be evaluated for the
   * 'use_dpop_nonce' error to determine whether the request
   * should be retried using a dpop nonce.
   */
  errorResponse: Oauth2ErrorResponse

  /**
   * The headers returned in the response. The 'DPoP-Nonce'
   * header will be extracted if the access token error response indicates so.
   * Will throw an error if the 'error' in the response is 'use_dpop_nonce' but the
   * headers does not contain the 'DPoP-Nonce' header value.
   */
  responseHeaders: FetchHeaders
}

export function shouldRetryAuthorizationServerRequestWithDPoPNonce(
  options: ShouldRetryAuthorizationServerRequestWithDpopNonceOptions
) {
  if (options.errorResponse.error !== 'use_dpop_nonce') {
    return {
      retry: false,
    } as const
  }

  const dpopNonce = extractDpopNonceFromHeaders(options.responseHeaders)
  if (!dpopNonce) {
    throw new Oauth2Error(
      `Error response error contains error 'use_dpop_nonce' but the response headers do not include a valid 'DPoP-Nonce' header value.`
    )
  }

  return {
    retry: true,
    dpopNonce,
  } as const
}

export interface ShouldRetryResourceRequestWithDpopNonceOptions {
  resourceUnauthorizedError: Oauth2ResourceUnauthorizedError

  /**
   * The headers returned in the resource request response. If the
   * headeres contain a 'WWW-Authenticate' header containing error value
   * of 'use_dpop_nonce', the 'DPoP-Nonce' header will be extracted.
   * Will throw an error if the 'error' in the 'WWW-Authenticate' header is 'use_dpop_nonce'
   * but the headers does not contain the 'DPoP-Nonce' header value.
   */
  responseHeaders: FetchHeaders
}

export function shouldRetryResourceRequestWithDPoPNonce(options: ShouldRetryResourceRequestWithDpopNonceOptions) {
  const useDpopNonceChallenge = options.resourceUnauthorizedError.wwwAuthenticateHeaders.find(
    (challenge) =>
      challenge.scheme === SupportedAuthenticationScheme.DPoP && challenge.error === Oauth2ErrorCodes.UseDpopNonce
  )

  if (!useDpopNonceChallenge) {
    return { retry: false } as const
  }

  const dpopNonce = extractDpopNonceFromHeaders(options.responseHeaders)
  if (!dpopNonce || typeof dpopNonce !== 'string') {
    throw new Oauth2Error(
      `Resource request error in 'WWW-Authenticate' response header contains error 'use_dpop_nonce' but the response headers do not include a valid 'DPoP-Nonce' value.`
    )
  }

  return {
    retry: true,
    dpopNonce,
  } as const
}
