import type { SupportedAuthenticationScheme } from '../access-token/verify-access-token'
import type { Oauth2ErrorCodes } from '../common/v-oauth2-error'

export interface WwwAuthenticateHeaderChallenge {
  scheme: SupportedAuthenticationScheme

  /**
   * Space delimited scope value that lists scopes required
   * to access this resource.
   */
  scope?: string

  /**
   * Error should only be undefined if no access token was provided at all
   */
  error?: Oauth2ErrorCodes | string
  error_description?: string

  /**
   * Additional payload items to include in the Www-Authenticate
   * header response.
   */
  additionalPayload?: Record<string, string>
}

export class Oauth2ResourceUnauthorizedError extends Error {
  public constructor(
    internalMessage: string,
    public readonly wwwAuthenticateHeaders: WwwAuthenticateHeaderChallenge | Array<WwwAuthenticateHeaderChallenge>
  ) {
    super(`${internalMessage}\n${JSON.stringify(wwwAuthenticateHeaders, null, 2)}`)
  }
}
