import { formatZodError } from '@openid4vc/utils'
import type { RequestLike } from '../common/z-common'
import { Oauth2ErrorCodes } from '../common/z-oauth2-error'
import { Oauth2ServerErrorResponseError } from '../error/Oauth2ServerErrorResponseError'
import { type ParseAuthorizationRequestResult, parseAuthorizationRequest } from './parse-authorization-request'
import {
  type AuthorizationRequest,
  zAuthorizationRequest,
  zAuthorizationRequestParsedUriParamsToJson,
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
  const parsedAuthorizationRequest = zAuthorizationRequestParsedUriParamsToJson
    .pipe(zAuthorizationRequest)
    .safeParse(options.authorizationRequest)

  if (!parsedAuthorizationRequest.success) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: `Error occured during validation of pushed authorization request.\n${formatZodError(parsedAuthorizationRequest.error)}`,
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
