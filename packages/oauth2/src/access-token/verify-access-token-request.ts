import { type CallbackContext, HashAlgorithm } from '../callbacks'
import { type VerifiedClientAttestationJwt, verifyClientAttestation } from '../client-attestation/clent-attestation'
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
import { Oauth2Error } from '../error/Oauth2Error'
import { Oauth2ServerErrorResponseError } from '../error/Oauth2ServerErrorResponseError'
import type { AuthorizationServerMetadata } from '../metadata/authorization-server/z-authorization-server-metadata'
import { type PkceCodeChallengeMethod, verifyPkce } from '../pkce'
import type {
  ParsedAccessTokenAuthorizationCodeRequestGrant,
  ParsedAccessTokenPreAuthorizedCodeRequestGrant,
} from './parse-access-token-request'
import type { AccessTokenRequest } from './z-access-token'

export interface VerifyAccessTokenRequestDpop {
  /**
   * Whether dpop is required
   */
  required?: boolean

  /**
   * The dpop jwt from the access token request
   */
  jwt?: string

  /**
   * The expected jwk thumbprint, and can be used to match a dpop provided in the authorization
   * request to the dpop key used for the access token request.
   */
  expectedJwkThumbprint?: string

  /**
   * Allowed dpop signing alg values. If not provided
   * any alg values are allowed and it's up to the `verifyJwtCallback`
   * to handle the alg.
   */
  allowedSigningAlgs?: string[]
}

export interface VerifyAccessTokenRequestClientAttestation {
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

  /**
   * The expected client id that is bound to the authorization session, and can be used to match the client id
   * provided in the authorization request to the client used for the access token request.
   */
  expectedClientId?: string
}

export interface VerifyAccessTokenRequestPkce {
  codeVerifier?: string

  codeChallenge: string
  codeChallengeMethod: PkceCodeChallengeMethod
}

export interface VerifyAccessTokenRequestReturn {
  dpop?: {
    /**
     * base64url encoding of the JWK SHA-256 Thumbprint (according to [RFC7638])
     * of the DPoP public key (in JWK format)
     */
    jwkThumbprint: string

    jwk: Jwk
  }

  clientAttestation?: {
    clientAttestation: VerifiedClientAttestationJwt
    clientAttestationPop: VerifiedClientAttestationPopJwt
  }
}

export interface VerifyPreAuthorizedCodeAccessTokenRequestOptions {
  authorizationServerMetadata: AuthorizationServerMetadata

  grant: ParsedAccessTokenPreAuthorizedCodeRequestGrant
  accessTokenRequest: AccessTokenRequest
  request: RequestLike

  expectedPreAuthorizedCode: string
  expectedTxCode?: string

  clientAttestation?: VerifyAccessTokenRequestClientAttestation
  dpop?: VerifyAccessTokenRequestDpop
  pkce?: VerifyAccessTokenRequestPkce

  preAuthorizedCodeExpiresAt?: Date
  now?: Date

  callbacks: Pick<CallbackContext, 'hash' | 'verifyJwt'>
}

export async function verifyPreAuthorizedCodeAccessTokenRequest(
  options: VerifyPreAuthorizedCodeAccessTokenRequestOptions
): Promise<VerifyAccessTokenRequestReturn> {
  if (options.pkce) {
    await verifyAccessTokenRequestPkce(options.pkce, options.callbacks)
  }

  const dpopResult = options.dpop
    ? await verifyAccessTokenRequestDpop(options.dpop, options.request, options.callbacks)
    : undefined

  const clientAttestationResult = options.clientAttestation
    ? await verifyAccessTokenRequestClientAttestation(
        options.clientAttestation,
        options.authorizationServerMetadata,
        options.callbacks,
        dpopResult?.jwkThumbprint,
        options.now
      )
    : undefined

  if (options.grant.preAuthorizedCode !== options.expectedPreAuthorizedCode) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidGrant,
      error_description: `Invalid 'pre-authorized_code' provided`,
    })
  }

  if (options.grant.txCode !== options.expectedTxCode) {
    // If they do not match there is an error
    // No tx_code was expected, but it was in the request
    if (!options.expectedTxCode) {
      // not expected but provided
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `Request contains 'tx_code' that was not expected`,
      })
    }

    // tx_code was expected but not provided
    if (!options.grant.txCode) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `Missing required 'tx_code' in request`,
      })
    }

    // tx_code was expected and provided, but wrong
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidGrant,
      error_description: `Invalid 'tx_code' provided`,
    })
  }

  if (options.preAuthorizedCodeExpiresAt) {
    const now = options.now ?? new Date()

    if (now.getTime() > options.preAuthorizedCodeExpiresAt.getTime()) {
      throw new Oauth2ServerErrorResponseError(
        {
          error: Oauth2ErrorCodes.InvalidGrant,
          error_description: `Expired 'pre-authorized_code' provided`,
        },
        {
          internalMessage: `The provided 'pre-authorized_code' in the request expired at '${options.preAuthorizedCodeExpiresAt.getTime()}', now is '${now.getTime()}'`,
        }
      )
    }
  }

  return { dpop: dpopResult, clientAttestation: clientAttestationResult }
}

export interface VerifyAuthorizationCodeAccessTokenRequestOptions {
  authorizationServerMetadata: AuthorizationServerMetadata

  grant: ParsedAccessTokenAuthorizationCodeRequestGrant
  accessTokenRequest: AccessTokenRequest
  request: RequestLike

  expectedCode: string

  clientAttestation?: VerifyAccessTokenRequestClientAttestation
  dpop?: VerifyAccessTokenRequestDpop
  pkce?: VerifyAccessTokenRequestPkce

  codeExpiresAt?: Date
  now?: Date

  callbacks: Pick<CallbackContext, 'hash' | 'verifyJwt'>
}

export async function verifyAuthorizationCodeAccessTokenRequest(
  options: VerifyAuthorizationCodeAccessTokenRequestOptions
): Promise<VerifyAccessTokenRequestReturn> {
  if (options.pkce) {
    await verifyAccessTokenRequestPkce(options.pkce, options.callbacks)
  }

  const dpopResult = options.dpop
    ? await verifyAccessTokenRequestDpop(options.dpop, options.request, options.callbacks)
    : undefined

  const clientAttestationResult = options.clientAttestation
    ? await verifyAccessTokenRequestClientAttestation(
        options.clientAttestation,
        options.authorizationServerMetadata,
        options.callbacks,
        dpopResult?.jwkThumbprint,
        options.now
      )
    : undefined

  if (options.grant.code !== options.expectedCode) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidGrant,
      error_description: `Invalid 'code' provided`,
    })
  }

  if (options.codeExpiresAt) {
    const now = options.now ?? new Date()

    if (now.getTime() > options.codeExpiresAt.getTime()) {
      throw new Oauth2ServerErrorResponseError(
        {
          error: Oauth2ErrorCodes.InvalidGrant,
          error_description: `Expired 'code' provided`,
        },
        {
          internalMessage: `The provided 'code' in the request expired at '${options.codeExpiresAt.getTime()}', now is '${now.getTime()}'`,
        }
      )
    }
  }

  return { dpop: dpopResult, clientAttestation: clientAttestationResult }
}
async function verifyAccessTokenRequestClientAttestation(
  options: VerifyAccessTokenRequestClientAttestation,
  authorizationServerMetadata: AuthorizationServerMetadata,
  callbacks: Pick<CallbackContext, 'verifyJwt' | 'hash'>,
  dpopJwkThumbprint?: string,
  now?: Date
) {
  if (!options.clientAttestationJwt || !options.clientAttestationPopJwt) {
    if (!options.required && !options.clientAttestationJwt && !options.clientAttestationPopJwt) {
      return undefined
    }

    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidClient,
      error_description: `Missing required client attestation parameters in access token request. Make sure to provide the '${oauthClientAttestationHeader}' and '${oauthClientAttestationPopHeader}' header values.`,
    })
  }

  const verifiedClientAttestation = await verifyClientAttestation({
    authorizationServer: authorizationServerMetadata.issuer,
    callbacks,
    clientAttestationJwt: options.clientAttestationJwt,
    clientAttestationPopJwt: options.clientAttestationPopJwt,
    now,
  })

  if (
    options.expectedClientId &&
    options.expectedClientId !== verifiedClientAttestation.clientAttestation.payload.sub
  ) {
    // Ensure the client id matches with the client id from the session
    throw new Oauth2ServerErrorResponseError(
      {
        error: Oauth2ErrorCodes.InvalidClient,
        error_description: `The client id '${verifiedClientAttestation.clientAttestation.payload.sub}' in the client attestation does not match the client id for the authorization.`,
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
            'Expected the DPoP JWK thumbprint value to match the JWK thumbprint of the client attestation confirmation JWK. Ensrue both DPoP and client attestation use the same key.',
        },
        {
          status: 401,
        }
      )
    }
  }

  return verifiedClientAttestation
}

async function verifyAccessTokenRequestDpop(
  options: VerifyAccessTokenRequestDpop,
  request: RequestLike,
  callbacks: Pick<CallbackContext, 'verifyJwt' | 'hash'>
) {
  if (options.required && !options.jwt) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidDpopProof,
      error_description: 'Missing required DPoP proof',
    })
  }

  if (!options.jwt) return undefined

  const { header, jwkThumbprint } = await verifyDpopJwt({
    callbacks,
    dpopJwt: options.jwt,
    request,
    allowedSigningAlgs: options.allowedSigningAlgs,
    expectedJwkThumbprint: options.expectedJwkThumbprint,
  })

  return {
    jwk: header.jwk,
    jwkThumbprint,
  }
}

async function verifyAccessTokenRequestPkce(
  options: VerifyAccessTokenRequestPkce,
  callbacks: Pick<CallbackContext, 'hash'>
) {
  if (options.codeChallenge && !options.codeVerifier) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: `Missing required 'code_verifier' in access token request`,
    })
  }

  if (!options.codeVerifier) return null

  try {
    await verifyPkce({
      callbacks,
      codeChallenge: options.codeChallenge,
      codeChallengeMethod: options.codeChallengeMethod,
      codeVerifier: options.codeVerifier,
    })
  } catch (error) {
    if (error instanceof Oauth2Error) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidGrant,
        error_description: error.message,
      })
    }
    throw error
  }
}
