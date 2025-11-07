import { zInteger } from '@openid4vc/utils'
import { z } from 'zod'
import { zAuthorizationRequest } from '../authorization-request/z-authorization-request.js'
import { zOauth2ErrorResponse } from '../common/z-oauth2-error.js'

/**
 * Schema for Interactive Authorization Request (initial request)
 *
 * Based on OpenID4VCI 1.1 Interactive Authorization Endpoint
 * Similar to PAR request but sent to interactive_authorization_endpoint
 */
export const zInteractiveAuthorizationRequest = z
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
 * Schema for Interactive Authorization Response - Status
 */
export const zInteractiveAuthorizationResponseStatus = z.enum([
  'require_interaction', // Additional interaction required
  'ok', // Authorization completed successfully
])

/**
 * Schema for Interactive Authorization Response - Interaction Type
 */
export const zInteractiveAuthorizationType = z.enum([
  'openid4vp_presentation', // Request OpenID4VP presentation
  'redirect_to_web', // Redirect to web browser
  // Custom interaction types can be added by extensions
])

/**
 * Schema for OpenID4VP Request embedded in IAE response
 *
 * The OpenID4VP library handles the complete request structure.
 * This schema only defines the minimal fields needed for the IAE response.
 */
export const zOpenid4vpRequest = z
  .object({
    // JWT containing the request (signed or unsigned)
    request: z.optional(z.string()),

    // Client identifier
    client_id: z.optional(z.string()),
  })
  .loose()

/**
 * Schema for Interaction Required Response
 *
 * Returned when the Authorization Server requires additional user interaction
 */
export const zInteractiveAuthorizationInteractionRequiredResponse = z
  .object({
    // Status indicating interaction is required
    status: z.literal('require_interaction'),

    // REQUIRED: Type of interaction required
    type: zInteractiveAuthorizationType,

    // REQUIRED: Session identifier for subsequent requests
    auth_session: z.string(),

    // For type='openid4vp_presentation': OpenID4VP Authorization Request
    openid4vp_request: z.optional(zOpenid4vpRequest),

    // For type='redirect_to_web': Request URI for PAR
    request_uri: z.optional(z.string()),
    expires_in: z.optional(zInteger),
  })
  .loose()

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
 * Schema for Interactive Authorization Error Response
 *
 * Based on RFC 9126 (PAR) error response with additional error codes
 */
export const zInteractiveAuthorizationErrorResponse = zOauth2ErrorResponse
  .extend({
    // No additional fields beyond standard OAuth2 error response
  })
  .loose()

/**
 * Union type for all possible Interactive Authorization Responses
 */
export const zInteractiveAuthorizationResponse = z.union([
  zInteractiveAuthorizationInteractionRequiredResponse,
  zInteractiveAuthorizationCodeResponse,
  zInteractiveAuthorizationErrorResponse,
])

/**
 * Type exports
 */
export type InteractiveAuthorizationRequest = z.input<typeof zInteractiveAuthorizationRequest>
export type InteractiveAuthorizationFollowUpRequest = z.input<typeof zInteractiveAuthorizationFollowUpRequest>
export type InteractiveAuthorizationResponseStatus = z.infer<typeof zInteractiveAuthorizationResponseStatus>
export type InteractiveAuthorizationType = z.infer<typeof zInteractiveAuthorizationType>
export type Openid4vpRequest = z.infer<typeof zOpenid4vpRequest>
export type InteractiveAuthorizationInteractionRequiredResponse = z.infer<
  typeof zInteractiveAuthorizationInteractionRequiredResponse
>
export type InteractiveAuthorizationCodeResponse = z.infer<typeof zInteractiveAuthorizationCodeResponse>
export type InteractiveAuthorizationErrorResponse = z.infer<typeof zInteractiveAuthorizationErrorResponse>
export type InteractiveAuthorizationResponse = z.infer<typeof zInteractiveAuthorizationResponse>

/**
 * Error code for missing interaction type
 */
export const InteractiveAuthorizationErrorCodes = {
  MissingInteractionType: 'missing_interaction_type',
} as const
