import {
  type AuthorizationServerMetadata,
  authorizationServerRequestWithDpopRetry,
  type CallbackContext,
  createDpopHeadersForRequest,
  extractDpopNonceFromHeaders,
  Oauth2Error,
  type RequestDpopOptions,
  zOauth2ErrorResponse,
} from '@openid4vc/oauth2'
import {
  ContentType,
  createZodFetcher,
  Headers,
  InvalidFetchResponseError,
  objectToQueryParams,
  parseWithErrorHandling,
  ValidationError,
} from '@openid4vc/utils'
import { Openid4vciClientInteractiveAuthorizationError } from '../error/Openid4vciClientInteractiveAuthorizationError'
import {
  type InteractiveAuthorizationFollowUpRequest,
  type InteractiveAuthorizationInitialRequest,
  zInteractiveAuthorizationFollowUpRequest,
  zInteractiveAuthorizationInitialRequest,
  zInteractiveAuthorizationResponse,
} from './z-interactive-authorization'

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
  request: InteractiveAuthorizationInitialRequest | InteractiveAuthorizationFollowUpRequest

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
 * @throws {Openid4vciClientInteractiveAuthorizationError} if the request failed and an error response is returned
 * @throws {InvalidFetchResponseError} if the request failed but no error response could be parsed
 * @throws {ValidationError} if a successful response was received but an error occurred during verification
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

  // Validate the request payload based on whether it's an initial or follow-up request
  const isFollowUpRequest = options.request.auth_session
  const interactiveAuthorizationRequest = isFollowUpRequest
    ? parseWithErrorHandling(
        zInteractiveAuthorizationFollowUpRequest,
        options.request,
        'Invalid interactive authorization follow-up request'
      )
    : parseWithErrorHandling(
        zInteractiveAuthorizationInitialRequest,
        options.request,
        'Invalid interactive authorization request'
      )

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
          body: objectToQueryParams(interactiveAuthorizationRequest).toString(),
          headers,
        }
      )

      if (!response.ok || !result) {
        const interactiveAuthorizationErrorResponse = zOauth2ErrorResponse.safeParse(
          await response
            .clone()
            .json()
            .catch(() => null)
        )
        if (interactiveAuthorizationErrorResponse.success) {
          throw new Openid4vciClientInteractiveAuthorizationError(
            `Error requesting authorization from interactive authorization endpoint '${authorizationServerMetadata.interactive_authorization_endpoint}'. Received response with status ${response.status}`,
            interactiveAuthorizationErrorResponse.data,
            response
          )
        }

        throw new InvalidFetchResponseError(
          `Error requesting authorization from interactive authorization endpoint '${authorizationServerMetadata.interactive_authorization_endpoint}'. Received response with status ${response.status}`,
          await response.clone().text(),
          response
        )
      }

      if (!result.success) {
        throw new ValidationError('Error validating interactive authorization response', result.error)
      }

      const dpopNonce = extractDpopNonceFromHeaders(response.headers) ?? undefined
      return {
        interactiveAuthorizationResponse: result.data,
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
