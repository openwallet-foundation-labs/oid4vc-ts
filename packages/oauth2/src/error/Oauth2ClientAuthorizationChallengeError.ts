import type { FetchResponse } from '@openid4vc/utils'
import type { AuthorizationChallengeErrorResponse } from '../authorization-challenge/z-authorization-challenge'
import { Oauth2ClientErrorResponseError } from './Oauth2ClientErrorResponseError'

export class Oauth2ClientAuthorizationChallengeError extends Oauth2ClientErrorResponseError {
  public constructor(
    message: string,
    public readonly errorResponse: AuthorizationChallengeErrorResponse,
    response: FetchResponse
  ) {
    super(message, errorResponse, response)
  }
}
