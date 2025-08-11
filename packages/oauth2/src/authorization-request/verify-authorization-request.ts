import { type CallbackContext, HashAlgorithm } from '../callbacks'
import { type VerifiedClientAttestationJwt, verifyClientAttestation } from '../client-attestation/client-attestation'
import type { VerifiedClientAttestationPopJwt } from '../client-attestation/client-attestation-pop'
import {
  oauthClientAttestationHeader,
  oauthClientAttestationPopHeader,
} from '../client-attestation/z-client-attestation'
import { calculateJwkThumbprint } from '../common/jwk/jwk-thumbprint'
import type { Jwk } from '../common/jwk/z-jwk'
import type { RequestLike } from '../common/z-common'
import { Oauth2ErrorCodes } from '../common/z-oauth2-error'
import { verifyDpopJwt } from '../dpop/dpop'
import { Oauth2ServerErrorResponseError } from '../error/Oauth2ServerErrorResponseError'
import type { AuthorizationServerMetadata } from '../metadata/authorization-server/z-authorization-server-metadata'

export interface VerifyAuthorizationRequestDpop {
  /**
   * Whether dpop is required.
   */
  required?: boolean

  /**
   * The dpop jwt from the pushed authorization request.
   *
   * If dpop is required, at least one of `jwt` or `jwkThumbprint` MUST
   * be provided. If both are provided, the jwk thumbprints are matched
   */
  jwt?: string

  /**
   * The jwk thumbprint as provided in the `dpop_jkt` parameter.
   *
   * If dpop is required, at least one of `jwt` or `jwkThumbprint` MUST
   * be provided. If both are provided, the jwk thumbprints are matched
   */
  jwkThumbprint?: string

  /**
   * Allowed dpop signing alg values. If not provided
   * any alg values are allowed and it's up to the `verifyJwtCallback`
   * to handle the alg.
   */
  allowedSigningAlgs?: string[]
}

export interface VerifyAuthorizationRequestClientAttestation {
  /**
   * Whether client attestation is required.
   */
  required?: boolean

  /**
   * Whether to ensure that the key used in client attestation confirmation
   * is the same key used for DPoP. This only has effect if both DPoP and client
   * attestations are present.
   *
   * @default false
   */
  ensureConfirmationKeyMatchesDpopKey?: boolean

  clientAttestationJwt?: string
  clientAttestationPopJwt?: string
}

export interface VerifyAuthorizationRequestReturn {
  dpop?: {
    /**
     * base64url encoding of the JWK SHA-256 Thumbprint (according to [RFC7638])
     * of the DPoP public key (in JWK format).
     *
     * This will always be returned if dpop is used for the PAR endpoint
     */
    jwkThumbprint: string

    /**
     * The JWK will be returned if a DPoP proof was provided in the header.
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

export interface VerifyAuthorizationRequestOptions {
  authorizationServerMetadata: AuthorizationServerMetadata

  authorizationRequest: {
    client_id?: string
  }
  request: RequestLike

  dpop?: VerifyAuthorizationRequestDpop
  clientAttestation?: VerifyAuthorizationRequestClientAttestation

  /**
   * Date to use for expiration. If not provided current date will be used.
   */
  now?: Date

  callbacks: Pick<CallbackContext, 'hash' | 'verifyJwt'>
}

// TODO: verify the request against the metadata
export async function verifyAuthorizationRequest(
  options: VerifyAuthorizationRequestOptions
): Promise<VerifyAuthorizationRequestReturn> {
  const dpopResult = options.dpop
    ? await verifyAuthorizationRequestDpop(options.dpop, options.request, options.callbacks, options.now)
    : undefined

  const clientAttestationResult = options.clientAttestation
    ? await verifyAuthorizationRequestClientAttestation(
        options.clientAttestation,
        options.authorizationServerMetadata,
        options.callbacks,
        dpopResult?.jwkThumbprint,
        options.now,
        options.authorizationRequest.client_id
      )
    : undefined

  return {
    dpop: dpopResult?.jwkThumbprint
      ? {
          jwkThumbprint: dpopResult.jwkThumbprint,
          jwk: dpopResult.jwk,
        }
      : undefined,
    clientAttestation: clientAttestationResult,
  }
}

async function verifyAuthorizationRequestClientAttestation(
  options: VerifyAuthorizationRequestClientAttestation,
  authorizationServerMetadata: AuthorizationServerMetadata,
  callbacks: Pick<CallbackContext, 'verifyJwt' | 'hash'>,
  dpopJwkThumbprint?: string,
  now?: Date,
  requestClientId?: string
) {
  if (!options.clientAttestationJwt || !options.clientAttestationPopJwt) {
    if (!options.required && !options.clientAttestationJwt && !options.clientAttestationPopJwt) {
      return undefined
    }

    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidClient,
      error_description: `Missing required client attestation parameters in pushed authorization request. Make sure to provide the '${oauthClientAttestationHeader}' and '${oauthClientAttestationPopHeader}' header values.`,
    })
  }

  const verifiedClientAttestation = await verifyClientAttestation({
    authorizationServer: authorizationServerMetadata.issuer,
    callbacks,
    clientAttestationJwt: options.clientAttestationJwt,
    clientAttestationPopJwt: options.clientAttestationPopJwt,
    now,
  })

  if (requestClientId && requestClientId !== verifiedClientAttestation.clientAttestation.payload.sub) {
    // Ensure the client id matches with the client id provided in the authorization request
    throw new Oauth2ServerErrorResponseError(
      {
        error: Oauth2ErrorCodes.InvalidClient,
        error_description: `The client_id '${requestClientId}' in the request does not match the client id '${verifiedClientAttestation.clientAttestation.payload.sub}' in the client attestation`,
      },
      {
        status: 401,
      }
    )
  }

  if (options.ensureConfirmationKeyMatchesDpopKey && dpopJwkThumbprint) {
    const clientAttestationJkt = await calculateJwkThumbprint({
      hashAlgorithm: HashAlgorithm.Sha256,
      hashCallback: callbacks.hash,
      jwk: verifiedClientAttestation.clientAttestation.payload.cnf.jwk,
    })

    if (clientAttestationJkt !== dpopJwkThumbprint) {
      throw new Oauth2ServerErrorResponseError(
        {
          error: Oauth2ErrorCodes.InvalidRequest,
          error_description:
            'Expected the DPoP JWK thumbprint value to match the JWK thumbprint of the client attestation confirmation JWK. Ensure both DPoP and client attestation use the same key.',
        },
        {
          status: 401,
        }
      )
    }
  }

  return verifiedClientAttestation
}

async function verifyAuthorizationRequestDpop(
  options: VerifyAuthorizationRequestDpop,
  request: RequestLike,
  callbacks: Pick<CallbackContext, 'verifyJwt' | 'hash'>,
  now?: Date
) {
  if (options.required && !options.jwt && !options.jwkThumbprint) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidDpopProof,
      error_description: `Missing required DPoP parameters in authorization request. Either DPoP header or 'dpop_jkt' is required.`,
    })
  }

  const verifyDpopResult = options.jwt
    ? await verifyDpopJwt({
        callbacks,
        dpopJwt: options.jwt,
        request,
        allowedSigningAlgs: options.allowedSigningAlgs,
        now,
      })
    : undefined

  if (options.jwkThumbprint && verifyDpopResult && options.jwkThumbprint !== verifyDpopResult.jwkThumbprint) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidDpopProof,
      error_description: `DPoP jwk thumbprint does not match with 'dpop_jkt' provided in authorization request`,
    })
  }

  return {
    jwk: verifyDpopResult?.header.jwk,
    jwkThumbprint: verifyDpopResult?.jwkThumbprint ?? options.jwkThumbprint,
  }
}
