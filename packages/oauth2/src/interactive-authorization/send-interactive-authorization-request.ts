import { ContentType, createZodFetcher, Headers, objectToQueryParams } from '@openid4vc/utils'
import type { CallbackContext } from '../callbacks.js'
import { createDpopHeadersForRequest, extractDpopNonceFromHeaders, type RequestDpopOptions } from '../dpop/dpop.js'
import { authorizationServerRequestWithDpopRetry } from '../dpop/dpop-retry.js'
import { Oauth2Error } from '../error/Oauth2Error.js'
import type { AuthorizationServerMetadata } from '../metadata/authorization-server/z-authorization-server-metadata.js'
import type {
  InteractiveAuthorizationFollowUpRequest,
  InteractiveAuthorizationRequest,
} from './z-interactive-authorization.js'
import { zInteractiveAuthorizationResponse } from './z-interactive-authorization.js'

export interface SendInteractiveAuthorizationRequestOptions {
  /**
   * Callback context
   */
  callbacks: Pick<CallbackContext, 'fetch' | 'signJwt' | 'hash' | 'generateRandom'>

  /**
   * Authorization server metadata containing the interactive_authorization_endpoint
   */
  authorizationServerMetadata: AuthorizationServerMetadata

  /**
   * The interactive authorization request parameters
   * Can be either an initial request or a follow-up request
   */
  request: InteractiveAuthorizationRequest | InteractiveAuthorizationFollowUpRequest

  /**
   * Optional DPoP configuration for request binding
   */
  dpop?: RequestDpopOptions

  /**
   * Optional headers to include in the request
   * Used for OAuth-Client-Attestation headers, etc.
   */
  additionalHeaders?: Record<string, string>
}

/**
 * Send an Interactive Authorization Request to the Authorization Server
 *
 * Implements the Interactive Authorization Endpoint flow from OpenID4VCI 1.1.
 * This endpoint enables complex authentication and authorization flows where
 * interaction occurs directly with the Wallet rather than being intermediated
 * by a browser.
 *
 * The request can be either:
 * - Initial request: Contains authorization parameters and interaction_types_supported
 * - Follow-up request: Contains auth_session and interaction-specific parameters
 *
 * @param options - Configuration options for the request
 * @returns The interactive authorization response and updated DPoP config
 * @throws {Oauth2Error} if the authorization server doesn't support interactive authorization
 *
 * @example Initial request
 * ```ts
 * const result = await sendInteractiveAuthorizationRequest({
 *   callbacks,
 *   authorizationServerMetadata,
 *   request: {
 *     response_type: 'code',
 *     client_id: 'my-client',
 *     interaction_types_supported: 'openid4vp_presentation,redirect_to_web',
 *     authorization_details: [...]
 *   }
 * })
 * ```
 *
 * @example Follow-up request with OpenID4VP response
 * ```ts
 * const result = await sendInteractiveAuthorizationRequest({
 *   callbacks,
 *   authorizationServerMetadata,
 *   request: {
 *     auth_session: 'session-123',
 *     openid4vp_response: JSON.stringify({ vp_token: '...' })
 *   }
 * })
 * ```
 */
export async function sendInteractiveAuthorizationRequest(options: SendInteractiveAuthorizationRequestOptions) {
  const fetchWithZod = createZodFetcher(options.callbacks.fetch)

  const authorizationServerMetadata = options.authorizationServerMetadata
  const interactiveAuthorizationEndpoint = authorizationServerMetadata.interactive_authorization_endpoint
  if (!interactiveAuthorizationEndpoint) {
    throw new Oauth2Error(
      `Unable to send interactive authorization request. Authorization server '${authorizationServerMetadata.issuer}' has no 'interactive_authorization_endpoint'`
    )
  }

  return authorizationServerRequestWithDpopRetry({
    dpop: options.dpop,
    request: async (dpop) => {
      const dpopHeaders = dpop
        ? await createDpopHeadersForRequest({
            request: {
              method: 'POST',
              url: interactiveAuthorizationEndpoint,
            },
            signer: dpop.signer,
            callbacks: options.callbacks,
            nonce: dpop.nonce,
          })
        : undefined

      const headers = new Headers({
        ...dpopHeaders,
        ...options.additionalHeaders,
        'Content-Type': ContentType.XWwwFormUrlencoded,
      })

      const { response, result } = await fetchWithZod(
        zInteractiveAuthorizationResponse,
        ContentType.Json,
        interactiveAuthorizationEndpoint,
        {
          method: 'POST',
          body: objectToQueryParams(options.request as Record<string, unknown>).toString(),
          headers,
        }
      )

      const dpopNonce = extractDpopNonceFromHeaders(response.headers) ?? undefined
      return {
        response: result?.data,
        dpop: dpop
          ? {
              ...dpop,
              nonce: dpopNonce,
            }
          : undefined,
      }
    },
  })
}
