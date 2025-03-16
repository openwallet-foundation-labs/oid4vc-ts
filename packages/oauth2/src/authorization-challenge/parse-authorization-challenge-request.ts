import { formatZodError } from '@openid4vc/utils'
import { extractClientAttestationJwtsFromHeaders } from '../client-attestation/clent-attestation'
import type { RequestLike } from '../common/z-common'
import { Oauth2ErrorCodes } from '../common/z-oauth2-error'
import { extractDpopJwtFromHeaders } from '../dpop/dpop'
import { Oauth2ServerErrorResponseError } from '../error/Oauth2ServerErrorResponseError'
import { type AuthorizationChallengeRequest, zAuthorizationChallengeRequest } from './z-authorization-challenge'

export interface ParseAuthorizationChallengeRequestOptions {
  request: RequestLike

  authorizationChallengeRequest: unknown
}

export interface ParseAuthorizationChallengeRequestResult {
  authorizationChallengeRequest: AuthorizationChallengeRequest

  /**
   * The dpop params from the authorization challenge request.
   *
   * Both `dpop_jkt` and DPoP header can be included in the request.
   *
   * The jkt and the signer of the jwt have not been verified against
   * each other yet, this only happens during verification
   */
  dpop?:
    | {
        jwkThumbprint: string
        jwt?: string
      }
    | {
        jwkThumbprint?: string
        jwt: string
      }

  /**
   * The client attestation jwts from the authorization challenge request headers.
   * These have not been verified yet.
   */
  clientAttestation?: {
    clientAttestationJwt: string
    clientAttestationPopJwt: string
  }
}

/**
 * Parse an authorization challenge request.
 *
 * @throws {Oauth2ServerErrorResponseError}
 */
export function parseAuthorizationChallengeRequest(
  options: ParseAuthorizationChallengeRequestOptions
): ParseAuthorizationChallengeRequestResult {
  // TODO: we should probably only verify/parse the auth challenge request AFTER we have verified the auth?
  // So we need to split this up into two methods
  // - parse authorization request authentication
  const parsedAuthorizationChallengeRequest = zAuthorizationChallengeRequest.safeParse(
    options.authorizationChallengeRequest
  )
  if (!parsedAuthorizationChallengeRequest.success) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: `Error occured during validation of authorization challenge request.\n${formatZodError(parsedAuthorizationChallengeRequest.error)}`,
    })
  }

  const authorizationChallengeRequest = parsedAuthorizationChallengeRequest.data

  // We only parse the dpop, we don't verify it yet
  const extractedDpopJwt = extractDpopJwtFromHeaders(options.request.headers)
  if (!extractedDpopJwt.valid) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidDpopProof,
      error_description: `Request contains a 'DPoP' header, but the value is not a valid DPoP jwt`,
    })
  }

  // We only parse the client attestations, we don't verify it yet
  const extractedClientAttestationJwts = extractClientAttestationJwtsFromHeaders(options.request.headers)
  if (!extractedClientAttestationJwts.valid) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidClient,
      error_description:
        'Request contains client attestation header, but the values are not valid client attestation and client attestation PoP header.',
    })
  }

  return {
    authorizationChallengeRequest,

    dpop: extractedDpopJwt.dpopJwt
      ? {
          jwt: extractedDpopJwt.dpopJwt,
          jwkThumbprint: authorizationChallengeRequest.dpop_jkt,
        }
      : // Basically the same as above, but with correct TS type hinting
        authorizationChallengeRequest.dpop_jkt
        ? {
            jwt: extractedDpopJwt.dpopJwt,
            jwkThumbprint: authorizationChallengeRequest.dpop_jkt,
          }
        : undefined,
    clientAttestation: extractedClientAttestationJwts.clientAttestationHeader
      ? {
          clientAttestationJwt: extractedClientAttestationJwts.clientAttestationHeader,
          clientAttestationPopJwt: extractedClientAttestationJwts.clientAttestationPopHeader,
        }
      : undefined,
  }
}
