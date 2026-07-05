import { Oauth2Error, type Oauth2ErrorOptions } from '@openid4vc/oauth2'
import type { Openid4vpAuthorizationErrorResponse } from './z-authorization-response'

/**
 * Error thrown when the wallet returns an OpenID4VP Authorization Error Response
 * (e.g. the wallet detected an error with the request, or is unavailable) instead
 * of a successful Authorization Response containing a `vp_token`.
 */
export class Openid4vpAuthorizationResponseError extends Oauth2Error {
  public constructor(
    message: string,
    public readonly errorResponse: Openid4vpAuthorizationErrorResponse,
    options?: Oauth2ErrorOptions
  ) {
    super(`${message}\n${JSON.stringify(errorResponse, null, 2)}`, options)
  }
}
