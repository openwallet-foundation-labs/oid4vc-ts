import type { Oauth2ErrorResponse } from '../common/v-oauth2-error'
import { Oauth2Error, type Oauth2ErrorOptions } from './Oauth2Error'

export class Oauth2ServerErrorResponseError extends Oauth2Error {
  public constructor(
    public readonly errorResponse: Oauth2ErrorResponse,
    internalMessage?: string,
    options?: Oauth2ErrorOptions
  ) {
    super(`${internalMessage ?? errorResponse.error_description}\n${JSON.stringify(errorResponse, null, 2)}`, options)
  }
}
