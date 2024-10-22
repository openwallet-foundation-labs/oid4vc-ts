import type { Oauth2ErrorResponse } from '../common/v-oauth2-error'

export class Oid4vcOauthErrorResponseError extends Error {
  public readonly response: Response

  public constructor(
    message: string,
    public readonly errorResponse: Oauth2ErrorResponse,
    response: Response
  ) {
    super(`${message}\n${JSON.stringify(errorResponse, null, 2)}`)
    this.response = response.clone()
  }
}
