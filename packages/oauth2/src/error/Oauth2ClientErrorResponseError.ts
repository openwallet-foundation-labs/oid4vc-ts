import type { FetchResponse } from '@openid4vc/utils'
import type { Oauth2ErrorResponse } from '../common/z-oauth2-error'
import { Oauth2Error } from './Oauth2Error'

export class Oauth2ClientErrorResponseError extends Oauth2Error {
  public readonly response: FetchResponse

  public constructor(
    message: string,
    public readonly errorResponse: Oauth2ErrorResponse,
    response: FetchResponse
  ) {
    super(`${message}\n${JSON.stringify(errorResponse, null, 2)}`)
    this.response = response.clone()
  }
}
