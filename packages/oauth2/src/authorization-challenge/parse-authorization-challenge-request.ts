import { parseWithErrorHandling } from '@openid4vc/utils'
import { vAuthorizationChallengeRequest } from './v-authorization-challenge'

export interface ParseAuthorizationChallengeRequestOptions {
  authorizationChallengeRequest: unknown
}

/**
 * Parse an authorization challenge request.
 *
 * @throws {ValidationError} if a successful response was received but an error occured during verification of the {@link AuthorizationChallengeResponse}
 */
export function parseAuthorizationChallengeRequest(options: ParseAuthorizationChallengeRequestOptions) {
  const authorizationChallengeRequest = parseWithErrorHandling(
    vAuthorizationChallengeRequest,
    options.authorizationChallengeRequest
  )

  return { authorizationChallengeRequest }
}
