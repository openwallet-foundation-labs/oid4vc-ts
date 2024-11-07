import type { Oauth2ErrorResponse } from '../common/v-oauth2-error'
import type { Oauth2ErrorOptions } from '../error/Oauth2Error'
import { Oauth2Error } from './Oauth2Error'

interface Oauth2ServerErrorResponseErrorOptions extends Oauth2ErrorOptions {
  internalMessage?: string

  /**
   * @default 400
   */
  status?: number
}

export class Oauth2ServerErrorResponseError extends Oauth2Error {
  public readonly status: number

  public constructor(
    public readonly errorResponse: Oauth2ErrorResponse,
    options?: Oauth2ServerErrorResponseErrorOptions
  ) {
    super(
      `${options?.internalMessage ?? errorResponse.error_description}\n${JSON.stringify(errorResponse, null, 2)}`,
      options
    )
    this.status = options?.status ?? 400
  }
}
