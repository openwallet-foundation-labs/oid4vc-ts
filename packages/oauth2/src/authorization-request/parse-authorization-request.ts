import { extractClientAttestationJwtsFromHeaders } from '../client-attestation/client-attestation'
import type { RequestLike } from '../common/z-common'
import { Oauth2ErrorCodes } from '../common/z-oauth2-error'
import { extractDpopJwtFromHeaders } from '../dpop/dpop'
import { Oauth2ServerErrorResponseError } from '../error/Oauth2ServerErrorResponseError'

export interface ParseAuthorizationRequestOptions {
  request: RequestLike

  authorizationRequest: {
    dpop_jkt?: string
  }
}

export interface ParseAuthorizationRequestResult {
  /**
   * The dpop params from the authorization request.
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

  // TODO: we should revampt this to generic client authentication so we can suppor other
  // method as well. We should also create a generic verify client authentication method.
  /**
   * The client attestation jwts from the authorization request headers.
   * These have not been verified yet.
   */
  clientAttestation?: {
    clientAttestationJwt: string
    clientAttestationPopJwt: string
  }
}

/**
 * Parse an authorization request.
 *
 * @throws {Oauth2ServerErrorResponseError}
 */
export function parseAuthorizationRequest(options: ParseAuthorizationRequestOptions): ParseAuthorizationRequestResult {
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
    dpop: extractedDpopJwt.dpopJwt
      ? {
          jwt: extractedDpopJwt.dpopJwt,
          jwkThumbprint: options.authorizationRequest.dpop_jkt,
        }
      : // Basically the same as above, but with correct TS type hinting
        options.authorizationRequest.dpop_jkt
        ? {
            jwt: extractedDpopJwt.dpopJwt,
            jwkThumbprint: options.authorizationRequest.dpop_jkt,
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
