import { formatZodError } from '@openid4vc/utils'
import type { RequestLike } from '../common/z-common'
import { Oauth2ErrorCodes } from '../common/z-oauth2-error'
import { Oauth2ServerErrorResponseError } from '../error/Oauth2ServerErrorResponseError'
import { type ParseAuthorizationRequestResult, parseAuthorizationRequest } from './parse-authorization-request'
import {
  type AuthorizationRequest,
  pushedAuthorizationRequestUriPrefix,
  zAuthorizationRequest,
} from './z-authorization-request'

export interface ParsePushedAuthorizationRequestOptions {
  request: RequestLike
  authorizationRequest: unknown
}
export interface ParsePushedAuthorizationRequestResult extends ParseAuthorizationRequestResult {
  authorizationRequest: AuthorizationRequest
}

/**
 * Parse an pushed authorization request.
 *
 * @throws {Oauth2ServerErrorResponseError}
 */
export function parsePushedAuthorizationRequest(
  options: ParsePushedAuthorizationRequestOptions
): ParsePushedAuthorizationRequestResult {
  const parsedAuthorizationRequest = zAuthorizationRequest.safeParse(options.authorizationRequest)
  if (!parsedAuthorizationRequest.success) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: `Error occurred during validation of pushed authorization request.\n${formatZodError(parsedAuthorizationRequest.error)}`,
    })
  }

  const authorizationRequest = parsedAuthorizationRequest.data
  const { clientAttestation, dpop } = parseAuthorizationRequest({
    authorizationRequest,
    request: options.request,
  })

  return {
    authorizationRequest,

    dpop,
    clientAttestation,
  }
}

export interface ParsePushedAuthorizationRequestUriReferenceValueOptions {
  uri: string
}

/**
 * Parse a pushed authorization request URI prefixed with `urn:ietf:params:oauth:request_uri:`
 * and returns the identifier, without the prefix.
 *
 * @throws {Oauth2ServerErrorResponseError}
 */
export function parsePushedAuthorizationRequestUriReferenceValue(
  options: ParsePushedAuthorizationRequestUriReferenceValueOptions
): string {
  if (!options.uri.startsWith(pushedAuthorizationRequestUriPrefix)) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: `The 'request_uri' must start with the prefix "${pushedAuthorizationRequestUriPrefix}".`,
    })
  }

  return options.uri.substring(pushedAuthorizationRequestUriPrefix.length)
}
