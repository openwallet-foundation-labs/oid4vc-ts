import { z } from 'zod'
import type { Openid4vpJarAuthorizationRequest } from '../jar/z-jar-authorization-request'
import type { Openid4vpAuthorizationRequest } from './z-authorization-request'
import { zOpenid4vpAuthorizationRequestDcApi } from './z-authorization-request-dc-api'

/**
 * Response modes for Interactive Authorization Endpoint (IAE) flow
 * Part of OpenID4VCI 1.1 specification
 */
const zOpenid4vpResponseModeIae = z.enum(['iae_post', 'iae_post.jwt'])

/**
 * Authorization Request schema for Interactive Authorization Endpoint (IAE) flow
 *
 * IAE is used in OpenID4VCI when the authorization server needs to interact
 * directly with the wallet (e.g., requesting credential presentation) as part
 * of the authorization process.
 *
 * Key differences from DC API:
 * - Uses iae_post/iae_post.jwt response modes
 * - Uses expected_url instead of expected_origins for signed requests
 * - Response is sent back to the Interactive Authorization Endpoint
 */
export const zOpenid4vpAuthorizationRequestIae = zOpenid4vpAuthorizationRequestDcApi
  .omit({
    response_mode: true,
    expected_origins: true,
  })
  .extend({
    response_mode: zOpenid4vpResponseModeIae,

    // OpenID4VCI 1.1 Interactive Authorization Endpoint - expected_url parameter
    // Used in signed requests to prevent replay attacks from malicious verifiers
    expected_url: z.string().optional(),

    // expected_url is used instead
    expected_origins: z.never().optional(),
  })

export type Openid4vpAuthorizationRequestIae = z.infer<typeof zOpenid4vpAuthorizationRequestIae>

export function isOpenid4vpResponseModeIae(
  responseMode: unknown
): responseMode is Openid4vpAuthorizationRequestIae['response_mode'] {
  return (
    responseMode !== undefined &&
    zOpenid4vpResponseModeIae.options.includes(responseMode as Openid4vpAuthorizationRequestIae['response_mode'])
  )
}

export function isOpenid4vpAuthorizationRequestIae(
  request: Openid4vpAuthorizationRequest | Openid4vpAuthorizationRequestIae | Openid4vpJarAuthorizationRequest
): request is Openid4vpAuthorizationRequestIae {
  return isOpenid4vpResponseModeIae(request.response_mode)
}
