import type { FetchResponse } from '@animo-id/oid4vc-utils'
import { Oauth2Error } from './Oauth2Error'

export class Oauth2InvalidFetchResponseError extends Oauth2Error {
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
