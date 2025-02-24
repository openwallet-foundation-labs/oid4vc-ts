import { parseWithErrorHandling } from '@openid4vc/utils'
import { zOpenid4vpAuthorizationResponse } from './z-authorization-response'

export function parseOpenid4VpAuthorizationResponsePayload(payload: Record<string, unknown>) {
  return parseWithErrorHandling(
    zOpenid4vpAuthorizationResponse,
    payload,
    'Failed to parse openid4vp authorization response.'
  )
}
