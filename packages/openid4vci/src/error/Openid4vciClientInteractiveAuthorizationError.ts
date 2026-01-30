import { Oauth2ClientErrorResponseError, type Oauth2ErrorResponse } from '@openid4vc/oauth2'
import type { FetchResponse } from '@openid4vc/utils'

export class Openid4vciClientInteractiveAuthorizationError extends Oauth2ClientErrorResponseError {
  public constructor(
    message: string,
    public readonly errorResponse: Oauth2ErrorResponse,
    response: FetchResponse
  ) {
    super(message, errorResponse, response)
  }
}
