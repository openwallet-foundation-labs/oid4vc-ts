import { encodeWwwAuthenticateHeader, parseWwwAuthenticateHeader } from '@openid4vc/utils'
import type { SupportedAuthenticationScheme } from '../access-token/verify-access-token'
import type { Oauth2ErrorCodes } from '../common/z-oauth2-error'
import { Oauth2Error } from './Oauth2Error'

export interface WwwAuthenticateHeaderChallenge {
  scheme: SupportedAuthenticationScheme | (string & {})

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

export class Oauth2ResourceUnauthorizedError extends Oauth2Error {
  public readonly wwwAuthenticateHeaders: WwwAuthenticateHeaderChallenge[]

  public constructor(
    internalMessage: string | undefined,
    wwwAuthenticateHeaders: WwwAuthenticateHeaderChallenge | Array<WwwAuthenticateHeaderChallenge>
  ) {
    super(`${internalMessage}\n${JSON.stringify(wwwAuthenticateHeaders, null, 2)}`)
    this.wwwAuthenticateHeaders = Array.isArray(wwwAuthenticateHeaders)
      ? wwwAuthenticateHeaders
      : [wwwAuthenticateHeaders]
  }

  static fromHeaderValue(value: string) {
    const headers = parseWwwAuthenticateHeader(value)
    return new Oauth2ResourceUnauthorizedError(
      undefined,
      headers.map(
        ({ scheme, payload: { error, error_description, scope, ...additionalPayload } }) =>
          ({
            scheme,
            error: Array.isArray(error) ? error.join(',') : (error ?? undefined),
            error_description: Array.isArray(error_description)
              ? error_description.join(',')
              : (error_description ?? undefined),
            scope: Array.isArray(scope) ? scope.join(',') : (scope ?? undefined),
            ...additionalPayload,
          }) satisfies WwwAuthenticateHeaderChallenge
      )
    )
  }

  public toHeaderValue() {
    return encodeWwwAuthenticateHeader(
      this.wwwAuthenticateHeaders.map((header) => ({
        scheme: header.scheme,
        payload: {
          error: header.error ?? null,
          error_description: header.error_description ?? null,
          scope: header.scope ?? null,
          ...header.additionalPayload,
        },
      }))
    )
  }
}
