import type { FetchResponse } from '@openid4vc/utils'
import { Oauth2Error } from './Oauth2Error'

export class InvalidFetchResponseError extends Oauth2Error {
  public readonly response: FetchResponse

  public constructor(
    message: string,
    public readonly textResponse: string,
    response: FetchResponse
  ) {
    super(`${message}\n${textResponse}`)
    this.response = response.clone()
  }
}
