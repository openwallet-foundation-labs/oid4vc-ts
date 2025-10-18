import { formatZodError } from '@openid4vc/utils'
import {
  type ParseAuthorizationRequestResult,
  parseAuthorizationRequest,
} from '../authorization-request/parse-authorization-request'
import { zAuthorizationRequestParsedUriParamsToJson } from '../authorization-request/z-authorization-request'
import type { RequestLike } from '../common/z-common'
import { Oauth2ErrorCodes } from '../common/z-oauth2-error'
import { Oauth2ServerErrorResponseError } from '../error/Oauth2ServerErrorResponseError'
import { type AuthorizationChallengeRequest, zAuthorizationChallengeRequest } from './z-authorization-challenge'

export interface ParseAuthorizationChallengeRequestOptions {
  request: RequestLike

  authorizationChallengeRequest: unknown
}

export interface ParseAuthorizationChallengeRequestResult extends ParseAuthorizationRequestResult {
  authorizationChallengeRequest: AuthorizationChallengeRequest
}

/**
 * Parse an authorization challenge request.
 *
 * @throws {Oauth2ServerErrorResponseError}
 */
export function parseAuthorizationChallengeRequest(
  options: ParseAuthorizationChallengeRequestOptions
): ParseAuthorizationChallengeRequestResult {
  // First ensure we correctly transform the serialized entries to JSON
  const parsedAuthorizationChallengeRequest = zAuthorizationRequestParsedUriParamsToJson
    .pipe(zAuthorizationChallengeRequest)
    .safeParse(options.authorizationChallengeRequest)

  if (!parsedAuthorizationChallengeRequest.success) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: `Error occurred during validation of authorization challenge request.\n${formatZodError(parsedAuthorizationChallengeRequest.error)}`,
    })
  }

  const authorizationChallengeRequest = parsedAuthorizationChallengeRequest.data
  const { clientAttestation, dpop } = parseAuthorizationRequest({
    authorizationRequest: authorizationChallengeRequest,
    request: options.request,
  })

  return {
    authorizationChallengeRequest: parsedAuthorizationChallengeRequest.data,

    dpop,
    clientAttestation,
  }
}
