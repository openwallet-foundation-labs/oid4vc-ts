import { formatZodError, URL } from '@openid4vc/utils'
import z from 'zod'
import { Oauth2ErrorCodes } from '../common/z-oauth2-error'
import { Oauth2ServerErrorResponseError } from '../error/Oauth2ServerErrorResponseError'
import {
  type AuthorizationErrorResponse,
  type AuthorizationResponse,
  zAuthorizationErrorResponse,
  zAuthorizationResponse,
} from './z-authorization-response'

export interface ParseAuthorizationResponseOptions {
  url: string
}

/**
 * Parse an authorization response redirect URL.
 *
 * @throws {Oauth2ServerErrorResponseError}
 */
export function parseAuthorizationResponseRedirectUrl(
  options: ParseAuthorizationResponseOptions
): AuthorizationResponse | AuthorizationErrorResponse {
  const searchParams = Object.fromEntries(new URL(options.url).searchParams)

  const parsedAuthorizationResponse = z
    .union([zAuthorizationErrorResponse, zAuthorizationResponse])
    .safeParse(searchParams)

  if (!parsedAuthorizationResponse.success) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: `Error occurred during validation of authorization response redirect URL.\n${formatZodError(parsedAuthorizationResponse.error)}`,
    })
  }

  return parsedAuthorizationResponse.data
}
