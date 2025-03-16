import { formatZodError } from '@openid4vc/utils'

import { extractClientAttestationJwtsFromHeaders } from '../client-attestation/clent-attestation'
import type { RequestLike } from '../common/z-common'
import { Oauth2ErrorCodes } from '../common/z-oauth2-error'
import { extractDpopJwtFromHeaders } from '../dpop/dpop'
import { Oauth2ServerErrorResponseError } from '../error/Oauth2ServerErrorResponseError'
import { type AuthorizationRequest, zAuthorizationRequest } from './z-authorization-request'

export interface ParsePushedAuthorizationRequestOptions {
  request: RequestLike

  authorizationRequest: unknown
}

// NOTE: can we do something to reduce duplication between
// PAR and authorization challenge request?
export interface ParsePushedAuthorizationRequestResult {
  authorizationRequest: AuthorizationRequest

  /**
   * The dpop params from the pushed authorization request.
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
   * The client attestation jwts from the pushed authorization request headers.
   * These have not been verified yet.
   */
  clientAttestation?: {
    clientAttestationJwt: string
    clientAttestationPopJwt: string
  }
}

/**
 * Parse an pushed authorization request.
 *
 * @throws {Oauth2ServerErrorResponseError}
 */
export function parsePushedAuthorizationRequest(
  options: ParsePushedAuthorizationRequestOptions
): ParsePushedAuthorizationRequestResult {
  // TODO: we should probably only verify/parse the pushed authorization request AFTER we have verified the auth?
  // So we need to split this up into two methods
  const parsedAuthorizationRequest = zAuthorizationRequest.safeParse(options.authorizationRequest)
  if (!parsedAuthorizationRequest.success) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: `Error occured during validation of pushed authorization request.\n${formatZodError(parsedAuthorizationRequest.error)}`,
    })
  }

  const authorizationRequest = parsedAuthorizationRequest.data

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
    authorizationRequest,

    dpop: extractedDpopJwt.dpopJwt
      ? {
          jwt: extractedDpopJwt.dpopJwt,
          jwkThumbprint: authorizationRequest.dpop_jkt,
        }
      : // Basically the same as above, but with correct TS type hinting
        authorizationRequest.dpop_jkt
        ? {
            jwt: extractedDpopJwt.dpopJwt,
            jwkThumbprint: authorizationRequest.dpop_jkt,
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
