import {} from '@openid4vc/oauth2'
import { parseWithErrorHandling } from '@openid4vc/utils'
import { isOpenid4vpAuthorizationRequestDcApi } from '../authorization-request/z-authorization-request-dc-api'
import type {} from '../jarm/jarm-auth-response/z-jarm-auth-response'
import { zOpenid4vpAuthorizationResponse } from './z-authorization-response'
import { zOpenid4vpAuthorizationResponseDcApi } from './z-authorization-response-dc-api'

export function parseOpenid4VpAuthorizationResponsePayload(payload: Record<string, unknown>) {
  if (isOpenid4vpAuthorizationRequestDcApi(payload)) {
    return parseWithErrorHandling(
      zOpenid4vpAuthorizationResponseDcApi,
      payload,
      'Failed to to parse openid4vp dc_api authorization response.'
    )
  }

  return parseWithErrorHandling(
    zOpenid4vpAuthorizationResponse,
    payload,
    'Failed to parse openid4vp authorization response.'
  )
}
