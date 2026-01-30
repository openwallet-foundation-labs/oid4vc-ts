import {
  type CallbackContext,
  decodeJwt,
  isJarAuthorizationRequest,
  Oauth2ErrorCodes,
  Oauth2ServerErrorResponseError,
  type ParseAuthorizationRequestResult,
  parseAuthorizationRequest,
  parseJarRequest,
  type RequestLike,
  zJarAuthorizationRequest,
} from '@openid4vc/oauth2'
import { formatZodError, parseWithErrorHandling } from '@openid4vc/utils'
import z from 'zod'
import type {
  InteractiveAuthorizationFollowUpRequest,
  InteractiveAuthorizationInitialRequest,
} from './z-interactive-authorization.js'
import {
  isInteractiveAuthorizationFollowUpRequest,
  zInteractiveAuthorizationFollowUpRequest,
  zInteractiveAuthorizationInitialRequest,
} from './z-interactive-authorization.js'

export enum InteractiveAuthorizationRequestType {
  Initial = 'Initial',
  FollowUp = 'FollowUp',
}

export interface ParseInteractiveAuthorizationRequestOptions {
  /**
   * The HTTP request object
   */
  request: RequestLike

  /**
   * The parsed request body (already decoded from form URL encoded)
   */
  interactiveAuthorizationRequest: unknown

  /**
   * Callbacks for fetching JAR request objects from request_uri
   */
  callbacks: Pick<CallbackContext, 'fetch'>
}

export interface ParseInteractiveAuthorizationInitialRequestResult extends ParseAuthorizationRequestResult {
  type: 'Initial'

  /**
   * The parsed interactive authorization request
   * Can be either an initial request or a follow-up request
   */
  interactiveAuthorizationRequest: InteractiveAuthorizationInitialRequest

  /**
   * The JWT-secured request object, if the request was sent as a JAR.
   * May be undefined if the request object is not a JAR.
   */
  interactiveAuthorizationRequestJwt?: string

  /**
   * List of interaction types supported by the wallet.
   */
  interactionTypesSupported: string[]
}

export interface ParseInteractiveAuthorizationFollowUpRequestResult {
  type: 'FollowUp'

  /**
   * The parsed interactive authorization request
   */
  interactiveAuthorizationRequest: InteractiveAuthorizationFollowUpRequest
}

/**
 * Parse an Interactive Authorization Request
 *
 * This function parses and validates an Interactive Authorization Endpoint request.
 * It automatically detects whether this is an initial request, a follow-up request,
 * or a JAR (JWT-secured) request based on the parameters present.
 *
 * @param options - Parsing options
 * @returns The parsed request and metadata
 * @throws {Oauth2ServerErrorResponseError} if validation fails
 *
 * @example Parse initial request
 * ```ts
 * const { interactiveAuthorizationRequest, isFollowUpRequest } = await parseInteractiveAuthorizationRequest({
 *   request: req,
 *   interactiveAuthorizationRequest: req.body,
 *   callbacks: { fetch }
 * })
 * // isFollowUpRequest = false
 * ```
 *
 * @example Parse follow-up request
 * ```ts
 * const { interactiveAuthorizationRequest, isFollowUpRequest } = await parseInteractiveAuthorizationRequest({
 *   request: req,
 *   interactiveAuthorizationRequest: req.body,
 *   callbacks: { fetch }
 * })
 * // isFollowUpRequest = true
 * ```
 *
 * @example Parse JAR request
 * ```ts
 * const { interactiveAuthorizationRequest, interactiveAuthorizationRequestJwt } = await parseInteractiveAuthorizationRequest({
 *   request: req,
 *   interactiveAuthorizationRequest: req.body,
 *   callbacks: { fetch }
 * })
 * // interactiveAuthorizationRequestJwt contains the signed JWT
 * ```
 */
export async function parseInteractiveAuthorizationRequest(
  options: ParseInteractiveAuthorizationRequestOptions
): Promise<ParseInteractiveAuthorizationFollowUpRequestResult | ParseInteractiveAuthorizationInitialRequestResult> {
  const parsed = parseWithErrorHandling(
    z.union([
      zInteractiveAuthorizationInitialRequest,
      zInteractiveAuthorizationFollowUpRequest,
      zJarAuthorizationRequest,
    ]),
    options.interactiveAuthorizationRequest,
    'Invalid interactive authorization request. Could not parse as initial request, follow-up request, or JAR request.'
  )

  // Check if it's a follow-up request first
  if (isInteractiveAuthorizationFollowUpRequest(parsed)) {
    // Follow-up requests have minimal parameters, so we don't parse authorization request details
    return {
      type: InteractiveAuthorizationRequestType.FollowUp,
      interactiveAuthorizationRequest: parsed,
    }
  }

  // Check if it's a JAR request
  let interactiveAuthorizationRequest: InteractiveAuthorizationInitialRequest
  let interactiveAuthorizationRequestJwt: string | undefined
  if (isJarAuthorizationRequest(parsed)) {
    // Parse the JAR request to get the JWT
    const parsedJar = await parseJarRequest({ jarRequestParams: parsed, callbacks: options.callbacks })
    const jwt = decodeJwt({ jwt: parsedJar.authorizationRequestJwt })

    const parsedInteractiveAuthorizationRequest = zInteractiveAuthorizationInitialRequest.safeParse(jwt.payload)
    if (!parsedInteractiveAuthorizationRequest.success) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `Invalid interactive authorization request. Could not parse JAR request payload.\n${formatZodError(parsedInteractiveAuthorizationRequest.error)}`,
      })
    }

    interactiveAuthorizationRequestJwt = parsedJar.authorizationRequestJwt
    interactiveAuthorizationRequest = parsedInteractiveAuthorizationRequest.data
  } else {
    // Regular (non-JAR) request - already validated by the union parse above
    interactiveAuthorizationRequest = parsed
  }

  const { clientAttestation, dpop } = parseAuthorizationRequest({
    authorizationRequest: interactiveAuthorizationRequest,
    request: options.request,
  })

  return {
    type: InteractiveAuthorizationRequestType.Initial,
    interactiveAuthorizationRequest,
    interactiveAuthorizationRequestJwt,
    dpop,
    clientAttestation,

    interactionTypesSupported: interactiveAuthorizationRequest.interaction_types_supported.split(','),
  }
}
