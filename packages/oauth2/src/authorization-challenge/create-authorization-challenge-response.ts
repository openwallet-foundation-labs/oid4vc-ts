import { type StringWithAutoCompletion, parseWithErrorHandling } from '@animo-id/oauth2-utils'
import type { Oauth2ErrorCodes } from '../common/v-oauth2-error'
import {
  type AuthorizationChallengeErrorResponse,
  type AuthorizationChallengeResponse,
  vAuthorizationChallengeErrorResponse,
  vAuthorizationChallengeResponse,
} from './v-authorization-challenge'

export interface CreateAuthorizationChallengeResponseOptions {
  /**
   * The authorization code
   */
  authorizationCode: string

  /**
   * Additional payload to include in the authorization challenge response.
   */
  additionalPayload?: Record<string, unknown>
}

/**
 * Create an authorization challenge response
 *
 * @throws {ValidationError} if an error occured during verification of the {@link AuthorizationChallengeResponse}
 */
export function createAuthorizationChallengeResponse(options: CreateAuthorizationChallengeResponseOptions) {
  const authorizationChallengeResponse = parseWithErrorHandling(vAuthorizationChallengeResponse, {
    ...options.additionalPayload,
    authorization_code: options.authorizationCode,
  } satisfies AuthorizationChallengeResponse)

  return { authorizationChallengeResponse }
}

export interface CreateAuthorizationChallengeErrorResponseOptions {
  /**
   * Auth session identifier for the authorization challenge. The client MUST include this
   * in subsequent requests to the authorization challenge endpoint.
   */
  authSession?: string

  /**
   * The presentation during issuance error.
   *
   * Error codes specific to authorization challenge are:
   *  - @see Oauth2ErrorCodes.RedirectToWeb
   *  - @see Oauth2ErrorCodes.InvalidSession
   *  - @see Oauth2ErrorCodes.InsufficientAuthorization
   *
   * If you want to require presentation of a
   */
  error: StringWithAutoCompletion<Oauth2ErrorCodes>

  /**
   * Optional error description
   */
  errorDescription?: string

  /**
   * OpenID4VP authorization request url that must be completed before authorization
   * can be granted
   *
   * Should be combined with `error` @see Oauth2ErrorCodes.InsufficientAuthorization
   */
  presentation?: string

  /**
   * Optional PAR request uri, allowing the authorization challenge request to be treated
   * as a succesfull pushed authorization request.
   *
   * Should be combined with `error` @see Oauth2ErrorCodes.RedirectToWeb
   */
  requestUri?: string

  /**
   * Duration is seconds after which the `requestUri` parameter will expire. Should only be included
   * if the `requestUri` is also included, and has no meaning otherwise
   */
  expiresIn?: number

  /**
   * Additional payload to include in the authorization challenge error response.
   */
  additionalPayload?: Record<string, unknown>
}

/**
 * Create an authorization challenge error response
 *
 * @throws {ValidationError} if an error occured during validation of the {@link AuthorizationChallengeErrorResponse}
 */
export function createAuthorizationChallengeErrorResponse(options: CreateAuthorizationChallengeErrorResponseOptions) {
  const authorizationChallengeErrorResponse = parseWithErrorHandling(vAuthorizationChallengeErrorResponse, {
    ...options.additionalPayload,

    // General FiPA
    error: options.error,
    error_description: options.errorDescription,
    auth_session: options.authSession,

    // Presentation during issuance
    presentation: options.presentation,

    // PAR
    request_uri: options.requestUri,
    expires_in: options.expiresIn,
  } satisfies AuthorizationChallengeErrorResponse)

  return authorizationChallengeErrorResponse
}
