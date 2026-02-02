import type { JarAuthorizationRequest } from '@openid4vc/oauth2'
import { zAuthorizationRequest } from '@openid4vc/oauth2'
import { zInteger } from '@openid4vc/utils'
import { z } from 'zod'

/**
 * Schema for Interactive Authorization Request (initial request)
 *
 * Based on OpenID4VCI 1.1 Interactive Authorization Endpoint
 * Similar to PAR request but sent to interactive_authorization_endpoint
 */
export const zInteractiveAuthorizationInitialRequest = z
  .object({
    // All authorization request params except response_type (always 'code' for IAE)
    ...zAuthorizationRequest.omit({ response_type: true }).shape,

    // REQUIRED: Comma-separated list of interaction types the Wallet supports
    interaction_types_supported: z.string(),

    // response_type is always 'code' for interactive authorization
    response_type: z.literal('code').default('code'),
  })
  .loose()

/**
 * Schema for Follow-up Interactive Authorization Request
 *
 * Follow-up requests include auth_session and interaction-specific parameters
 */
export const zInteractiveAuthorizationFollowUpRequest = z
  .object({
    // REQUIRED in follow-up requests
    auth_session: z.string(),

    // OPTIONAL: OpenID4VP Authorization Response (JSON-encoded object)
    // Present when responding to openid4vp_presentation interaction
    openid4vp_response: z.optional(z.string()),

    // OPTIONAL: PKCE code verifier
    // Present when following up after redirect_to_web with PKCE
    code_verifier: z.optional(z.string()),
  })
  .loose()

/**
 * Base schema for Interaction Required Response
 *
 * Contains fields common to all interaction types
 */
const zInteractiveAuthorizationInteractionRequiredResponseBase = z.object({
  // Status indicating interaction is required
  status: z.literal('require_interaction'),

  // REQUIRED: Session identifier for subsequent requests
  auth_session: z.string(),

  // Optional expiration time
  expires_in: z.optional(zInteger),
})

/**
 * Schema for OpenID4VP Presentation Interaction Response
 *
 * Returned when the Authorization Server requires an OpenID4VP presentation
 */
export const zInteractiveAuthorizationOpenid4vpPresentationResponse =
  zInteractiveAuthorizationInteractionRequiredResponseBase
    .extend({
      // Type is openid4vp_presentation
      type: z.literal('openid4vp_presentation'),

      // REQUIRED for openid4vp_presentation: OpenID4VP Authorization Request
      openid4vp_request: z.record(z.string(), z.unknown()),
    })
    .loose()

/**
 * Schema for Redirect to Web Interaction Response
 *
 * Returned when the Authorization Server requires a browser redirect
 */
export const zInteractiveAuthorizationRedirectToWebResponse = zInteractiveAuthorizationInteractionRequiredResponseBase
  .extend({
    // Type is redirect_to_web
    type: z.literal('redirect_to_web'),

    // REQUIRED for redirect_to_web: Request URI for PAR
    request_uri: z.string(),
  })
  .loose()

/**
 * Schema for Interaction Required Response (discriminated union)
 *
 * Returned when the Authorization Server requires additional user interaction.
 * Uses discriminated union on 'type' field for better type inference.
 */
export const zInteractiveAuthorizationInteractionRequiredResponse = z.discriminatedUnion('type', [
  zInteractiveAuthorizationOpenid4vpPresentationResponse,
  zInteractiveAuthorizationRedirectToWebResponse,
])

/**
 * Schema for Authorization Code Response
 *
 * Returned when authorization is successfully completed
 */
export const zInteractiveAuthorizationCodeResponse = z
  .object({
    // Status indicating success
    status: z.literal('ok'),

    // REQUIRED: Authorization code
    code: z.string(),
  })
  .loose()

/**


/**
 * Union type for all possible Interactive Authorization Responses
 */
export const zInteractiveAuthorizationResponse = z.union([
  zInteractiveAuthorizationInteractionRequiredResponse,
  zInteractiveAuthorizationCodeResponse,
])

/**
 * Type exports
 */
export type InteractiveAuthorizationInitialRequest = z.input<typeof zInteractiveAuthorizationInitialRequest>
export type InteractiveAuthorizationFollowUpRequest = z.input<typeof zInteractiveAuthorizationFollowUpRequest>

// Discriminated union member types
export type InteractiveAuthorizationOpenid4vpPresentationResponse = z.infer<
  typeof zInteractiveAuthorizationOpenid4vpPresentationResponse
>
export type InteractiveAuthorizationRedirectToWebResponse = z.infer<
  typeof zInteractiveAuthorizationRedirectToWebResponse
>

// Union type for all interaction required responses
export type InteractiveAuthorizationInteractionRequiredResponse = z.infer<
  typeof zInteractiveAuthorizationInteractionRequiredResponse
>

export type InteractiveAuthorizationCodeResponse = z.infer<typeof zInteractiveAuthorizationCodeResponse>
export type InteractiveAuthorizationResponse = z.infer<typeof zInteractiveAuthorizationResponse>

export type InteractiveAuthorizationRequest =
  | JarAuthorizationRequest
  | InteractiveAuthorizationFollowUpRequest
  | InteractiveAuthorizationInitialRequest

/**
 * Type guard to check if a request is a JAR Interactive Authorization Request
 */
export function isInteractiveAuthorizationFollowUpRequest(
  request: InteractiveAuthorizationRequest
): request is InteractiveAuthorizationFollowUpRequest {
  return request.auth_session !== undefined
}

/**
 * Type guard to check if a request is a JAR Interactive Authorization Request
 */
export function isInteractiveAuthorizationInitialRequest(
  request: InteractiveAuthorizationRequest
): request is InteractiveAuthorizationInitialRequest {
  return request.auth_session === undefined
}
