import type { Oauth2ErrorResponse } from '../common/v-oauth2-error'
import type { FetchResponse } from '../globals'

export class Oid4vcOauthErrorResponseError extends Error {
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
