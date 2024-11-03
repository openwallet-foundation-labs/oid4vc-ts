import type { Oauth2ErrorResponse } from '../common/v-oauth2-error'

export class Oauth2ServerErrorResponseError extends Error {
  public constructor(
    public readonly errorResponse: Oauth2ErrorResponse,
    internalMessage?: string
  ) {
    super(`${internalMessage ?? errorResponse.error_description}\n${JSON.stringify(errorResponse, null, 2)}`)
  }
}
