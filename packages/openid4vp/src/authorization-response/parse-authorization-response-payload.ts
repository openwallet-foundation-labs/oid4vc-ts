import { parseWithErrorHandling } from '@openid4vc/utils'
import { Openid4vpAuthorizationResponseError } from './Openid4vpAuthorizationResponseError'
import { zOpenid4vpAuthorizationErrorResponse, zOpenid4vpAuthorizationResponse } from './z-authorization-response'

export function parseOpenid4VpAuthorizationResponsePayload(payload: Record<string, unknown>) {
  // A wallet can return an authorization error response (e.g. if it detected an error
  // with the request, or is unavailable) instead of a successful authorization response.
  // We detect this based on the presence of the `error` parameter and throw a dedicated
  // error, instead of a confusing zod error about the missing `vp_token`.
  if (typeof payload.error === 'string') {
    const errorResponse = parseWithErrorHandling(
      zOpenid4vpAuthorizationErrorResponse,
      payload,
      'Failed to parse openid4vp authorization error response.'
    )

    throw new Openid4vpAuthorizationResponseError(
      'The wallet returned an openid4vp authorization error response.',
      errorResponse
    )
  }

  return parseWithErrorHandling(
    zOpenid4vpAuthorizationResponse,
    payload,
    'Failed to parse openid4vp authorization response.'
  )
}
