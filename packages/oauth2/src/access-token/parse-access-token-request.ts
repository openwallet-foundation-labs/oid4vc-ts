import { valibotRecursiveFlattenIssues } from '@openid4vc/utils'
import type { RequestLike } from '../common/v-common'
import { Oauth2ErrorCodes } from '../common/v-oauth2-error'
import { extractDpopJwtFromHeaders } from '../dpop/dpop'
import { Oauth2ServerErrorResponseError } from '../error/Oauth2ServerErrorResponseError'
import {
  type AuthorizationCodeGrantIdentifier,
  type PreAuthorizedCodeGrantIdentifier,
  authorizationCodeGrantIdentifier,
  preAuthorizedCodeGrantIdentifier,
} from '../v-grant-type'
import { type AccessTokenRequest, vAccessTokenRequest } from './v-access-token'

export interface ParsedAccessTokenPreAuthorizedCodeRequestGrant {
  grantType: PreAuthorizedCodeGrantIdentifier
  preAuthorizedCode: string
  txCode?: string
}

export interface ParsedAccessTokenAuthorizationCodeRequestGrant {
  grantType: AuthorizationCodeGrantIdentifier
  code: string
}

type ParsedAccessTokenRequestGrant =
  | ParsedAccessTokenPreAuthorizedCodeRequestGrant
  | ParsedAccessTokenAuthorizationCodeRequestGrant

export interface ParseAccessTokenRequestResult {
  accessTokenRequest: AccessTokenRequest
  grant: ParsedAccessTokenRequestGrant

  /**
   * The dpop jwt from the access token request headers
   */
  dpopJwt?: string

  /**
   * The pkce code verifier from the access token request
   */
  pkceCodeVerifier?: string
}

export interface ParseAccessTokenRequestOptions {
  request: RequestLike

  /**
   * The access token request as a JSON object. Your server should decode the
   * `x-www-url-form-urlencoded` body into an object (e.g. using `bodyParser.urlEncoed()` in express)
   */
  accessTokenRequest: Record<string, unknown>
}

/**
 * Parse access token request and extract the grant specific properties.
 *
 * If something goes wrong, such as the grant is not supported, missing parameters, etc,
 * it will throw `Oauth2ServerErrorResponseError` containing an error response object
 * that can be returned to the client.
 */
export function parseAccessTokenRequest(options: ParseAccessTokenRequestOptions): ParseAccessTokenRequestResult {
  const parsedAccessTokenRequest = vAccessTokenRequest.safeParse(options.accessTokenRequest)
  if (!parsedAccessTokenRequest.success) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: `Error occured during validation of authorization request.\n${JSON.stringify(valibotRecursiveFlattenIssues(parsedAccessTokenRequest.error.issues), null, 2)}`,
    })
  }

  const accessTokenRequest = parsedAccessTokenRequest.data
  let grant: ParsedAccessTokenRequestGrant

  if (accessTokenRequest.grant_type === preAuthorizedCodeGrantIdentifier) {
    if (!accessTokenRequest['pre-authorized_code']) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `Missing required 'pre-authorized_code' for grant type '${preAuthorizedCodeGrantIdentifier}'`,
      })
    }

    grant = {
      grantType: preAuthorizedCodeGrantIdentifier,
      preAuthorizedCode: accessTokenRequest['pre-authorized_code'],
      txCode: accessTokenRequest.tx_code,
    }
  } else if (accessTokenRequest.grant_type === authorizationCodeGrantIdentifier) {
    if (!accessTokenRequest.code) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `Missing required 'code' for grant type '${authorizationCodeGrantIdentifier}'`,
      })
    }

    grant = {
      grantType: authorizationCodeGrantIdentifier,
      code: accessTokenRequest.code,
    }
  } else {
    // Unsupported grant type
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.UnsupportedGrantType,
      error_description: `The grant type '${accessTokenRequest.grant_type}' is not supported`,
    })
  }

  // We only parse the dpop, we don't verify it yet
  const extractedDpopJwt = extractDpopJwtFromHeaders(options.request.headers)
  if (!extractedDpopJwt.valid) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidDpopProof,
      error_description: `Request contains a 'DPoP' header, but the value is not a valid DPoP jwt`,
    })
  }

  const pkceCodeVerifier = accessTokenRequest.code_verifier

  return {
    accessTokenRequest,
    grant,

    dpopJwt: extractedDpopJwt.dpopJwt,
    pkceCodeVerifier,
  }
}
