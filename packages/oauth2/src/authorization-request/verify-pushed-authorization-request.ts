import type { CallbackContext } from '../callbacks'
import { type VerifiedClientAttestationJwt, verifyClientAttestation } from '../client-attestation/clent-attestation'
import type { VerifiedClientAttestationPopJwt } from '../client-attestation/client-attestation-pop'
import type { Jwk } from '../common/jwk/z-jwk'
import type { RequestLike } from '../common/z-common'
import { Oauth2ErrorCodes } from '../common/z-oauth2-error'
import { verifyDpopJwt } from '../dpop/dpop'
import { Oauth2ServerErrorResponseError } from '../error/Oauth2ServerErrorResponseError'
import type { AuthorizationServerMetadata } from '../metadata/authorization-server/z-authorization-server-metadata'
import type { PkceCodeChallengeMethod } from '../pkce'
import type { AuthorizationRequest } from './z-authorization-request'

export interface VerifyPushedAuthorizationRequestDpop {
  /**
   * Whether dpop is required.
   */
  required?: boolean

  /**
   * The dpop jwt from the pushed authorization request.
   *
   * If dpop is required, at least one of `jwt` or `jwkThumbprint` MUST
   * be provided. If both are provided, the jwk thubmprints are matched
   */
  jwt?: string

  /**
   * The jwk thumbprint as provided in the `dpop_jkt` parameter.
   *
   * If dpop is required, at least one of `jwt` or `jwkThumbprint` MUST
   * be provided. If both are provided, the jwk thubmprints are matched
   */
  jwkThumbprint?: string

  /**
   * Allowed dpop signing alg values. If not provided
   * any alg values are allowed and it's up to the `verifyJwtCallback`
   * to handle the alg.
   */
  allowedSigningAlgs?: string[]
}

export interface VerifyAccessTokenRequestPkce {
  codeVerifier?: string

  codeChallenge: string
  codeChallengeMethod: PkceCodeChallengeMethod
}

export interface VerifyPushedAuthorizationRequestReturn {
  dpop?: {
    /**
     * base64url encoding of the JWK SHA-256 Thumbprint (according to [RFC7638])
     * of the DPoP public key (in JWK format).
     *
     * This will always be returned if dpop is used for the PAR endpoint
     */
    jwkThumbprint: string

    /**
     * The JWK will be returend if a DPoP proof was provided in the header.
     */
    jwk?: Jwk
  }

  /**
   * The verified client attestation if any were provided.
   */
  clientAttestation?: {
    clientAttestation: VerifiedClientAttestationJwt
    clientAttestationPop: VerifiedClientAttestationPopJwt
  }
}

export interface VerifyPushedAuthorizationRequestOptions {
  authorizationServerMetadata: AuthorizationServerMetadata

  authorizationRequest: AuthorizationRequest
  request: RequestLike

  dpop?: VerifyPushedAuthorizationRequestDpop

  clientAttestation?: {
    // TODO: add required?: boolean param like with dpop to easily make client attestations required.
    clientAttestationJwt: string
    clientAttestationPopJwt: string
  }

  now?: Date
  callbacks: Pick<CallbackContext, 'hash' | 'verifyJwt'>
}

// TODO: verify the request against the metadata
export async function verifyPushedAuthorizationRequest(
  options: VerifyPushedAuthorizationRequestOptions
): Promise<VerifyPushedAuthorizationRequestReturn> {
  const verifiedClientAttestation = options.clientAttestation
    ? await verifyClientAttestation({
        authorizationServer: options.authorizationServerMetadata.issuer,
        callbacks: options.callbacks,
        ...options.clientAttestation,
      })
    : undefined

  // Ensure the client id matches with the client id provided in the authorization request
  if (
    verifiedClientAttestation &&
    options.authorizationRequest.client_id !== verifiedClientAttestation.clientAttestation.payload.sub
  ) {
    throw new Oauth2ServerErrorResponseError(
      {
        error: Oauth2ErrorCodes.InvalidClient,
        error_description: `The client_id '${options.authorizationRequest.client_id}' in the request does not match the client id '${verifiedClientAttestation.clientAttestation.payload.sub}' in the client attestation`,
      },
      {
        status: 401,
      }
    )
  }

  const dpopResult = options.dpop
    ? await verifyPushedAuthorizationRequestDpop(options.dpop, options.request, options.callbacks)
    : undefined

  return {
    dpop: dpopResult?.jwkThumbprint
      ? {
          jwkThumbprint: dpopResult.jwkThumbprint,
          jwk: dpopResult.jwk,
        }
      : undefined,
    clientAttestation: verifiedClientAttestation,
  }
}

async function verifyPushedAuthorizationRequestDpop(
  options: VerifyPushedAuthorizationRequestDpop,
  request: RequestLike,
  callbacks: Pick<CallbackContext, 'verifyJwt' | 'hash'>
) {
  if (options.required && !options.jwt && !options.jwkThumbprint) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidDpopProof,
      error_description: `Missing required DPoP parameters in pushed authorization request. Either DPoP header or 'dpop_jkt' is required.`,
    })
  }

  const verifyDpopResult = options.jwt
    ? await verifyDpopJwt({
        callbacks,
        dpopJwt: options.jwt,
        request,
        allowedSigningAlgs: options.allowedSigningAlgs,
      })
    : undefined

  if (options.jwkThumbprint && verifyDpopResult && options.jwkThumbprint !== verifyDpopResult.jwkThumbprint) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidDpopProof,
      error_description: `DPoP jwk thumbprint does not match with 'dpop_jkt' provided in pushed authorization request`,
    })
  }

  return {
    jwk: verifyDpopResult?.header.jwk,
    jwkThumbprint: verifyDpopResult?.jwkThumbprint ?? options.jwkThumbprint,
  }
}
