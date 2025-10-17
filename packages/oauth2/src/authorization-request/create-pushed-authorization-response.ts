import { parseWithErrorHandling, type StringWithAutoCompletion } from '@openid4vc/utils'
import { zAccessTokenErrorResponse } from '../access-token/z-access-token'
import type { Oauth2ErrorCodes } from '../common/z-oauth2-error'
import {
  type PushedAuthorizationErrorResponse,
  type PushedAuthorizationResponse,
  zPushedAuthorizationResponse,
} from './z-authorization-request'

export interface CreatePushedAuthorizationResponseOptions {
  /**
   * The request uri where the client should redirect to
   */
  requestUri: string

  /**
   * Number of seconds after which the `requestUri` will expire.
   */
  expiresInSeconds: number

  /**
   * Additional payload to include in the pushed authorization response.
   */
  additionalPayload?: Record<string, unknown>
}

/**
 * Create an pushed authorization response
 *
 * @throws {ValidationError} if an error occured during verification of the {@link PushedAuthorizationResponse}
 */
export function createPushedAuthorizationResponse(options: CreatePushedAuthorizationResponseOptions) {
  const pushedAuthorizationResponse = parseWithErrorHandling(zPushedAuthorizationResponse, {
    ...options.additionalPayload,
    expires_in: options.expiresInSeconds,
    request_uri: options.requestUri,
  } satisfies PushedAuthorizationResponse)

  return { pushedAuthorizationResponse }
}

export interface CreatePushedAuthorizationErrorResponseOptions {
  /**
   * The pushed authorization error
   */
  error: StringWithAutoCompletion<Oauth2ErrorCodes>

  /**
   * Optional error description
   */
  errorDescription?: string

  /**
   * Additional payload to include in the pushed authorization error response.
   */
  additionalPayload?: Record<string, unknown>
}

/**
 * Create a pushed authorization error response
 *
 * @throws {ValidationError} if an error occured during validation of the {@link PushedAuthorizationErrorResponse}
 */
export function createPushedAuthorizationErrorResponse(options: CreatePushedAuthorizationErrorResponseOptions) {
  const pushedAuthorizationErrorResponse = parseWithErrorHandling(zAccessTokenErrorResponse, {
    ...options.additionalPayload,
    error: options.error,
    error_description: options.errorDescription,
  } satisfies PushedAuthorizationErrorResponse)

  return pushedAuthorizationErrorResponse
}
