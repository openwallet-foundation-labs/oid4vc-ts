import { Oid4vcError } from '../../error/Oid4vcError'
import type { FetchHeaders } from '../../utils/valibot-fetcher'
import type { AccessTokenErrorResponse } from '../access-token/v-access-token'
import { extractDpopNonceFromHeaders } from './dpop'

export interface ShouldRetryTokenRequestWithDpopNonceOptions {
  /**
   * The token error response that will be evaluated for the
   * 'use_dpop_nonce' error to determine whether the request
   * should be retried using a dpop nonce.
   */
  tokenErrorResponse: AccessTokenErrorResponse

  /**
   * The headers returned in the access token response. The 'DPoP-Nonce'
   * header will be extracted if the access token error response indicates so.
   * Will throw an error if the 'error' in the response is 'use_dpop_nonce' but the
   * headers does not contain the 'DPoP-Nonce' header value.
   */
  responseHeaders: FetchHeaders
}

export function shouldRetryTokenRequestWithDPoPNonce(options: ShouldRetryTokenRequestWithDpopNonceOptions) {
  if (options.tokenErrorResponse.error !== 'use_dpop_nonce') {
    return {
      retry: false,
    } as const
  }

  const dpopNonce = extractDpopNonceFromHeaders(options.responseHeaders)
  if (!dpopNonce) {
    throw new Oid4vcError(
      `Access token response error contains error 'use_dpop_nonce' but the access token response headers do not include a valid 'DPoP-Nonce' header value.`
    )
  }

  return {
    retry: true,
    dpopNonce,
  } as const
}

export interface ShouldRetryResourceRequestWithDpopNonceOptions {
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
  const wwwAuthenticateHeader = options.responseHeaders.get('WWW-Authenticate')
  if (typeof wwwAuthenticateHeader !== 'string' || !wwwAuthenticateHeader.includes('use_dpop_nonce')) {
    return { retry: false } as const
  }

  const dpopNonce = extractDpopNonceFromHeaders(options.responseHeaders)
  if (!dpopNonce || typeof dpopNonce !== 'string') {
    throw new Oid4vcError(
      `Resource request error in 'WWW-Authenticate' response header contains error 'use_dpop_nonce' but the response headers do not include a valid 'DPoP-Nonce' value.`
    )
  }

  return {
    retry: true,
    dpopNonce,
  } as const
}
