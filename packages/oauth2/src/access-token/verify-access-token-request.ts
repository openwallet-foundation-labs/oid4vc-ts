import type { CallbackContext } from '../callbacks'
import type { Jwk } from '../common/jwk/z-jwk'
import type { RequestLike } from '../common/z-common'
import { Oauth2ErrorCodes } from '../common/z-oauth2-error'
import { verifyDpopJwt } from '../dpop/dpop'
import { Oauth2Error } from '../error/Oauth2Error'
import { Oauth2ServerErrorResponseError } from '../error/Oauth2ServerErrorResponseError'
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

export interface VerifyAccessTokenRequestReturn {
  dpopJwk?: Jwk
}

export interface VerifyPreAuthorizedCodeAccessTokenRequestOptions {
  grant: ParsedAccessTokenPreAuthorizedCodeRequestGrant
  accessTokenRequest: AccessTokenRequest
  request: RequestLike

  expectedPreAuthorizedCode: string
  expectedTxCode?: string

  dpop?: VerifyAccessTokenRequestDpop
  pkce?: VerifyAccessTokenRequestPkce

  preAuthorizedCodeExpiresAt?: Date
  now?: Date

  callbacks: Pick<CallbackContext, 'hash' | 'verifyJwt'>
}

export async function verifyPreAuthorizedCodeAccessTokenRequest(
  options: VerifyPreAuthorizedCodeAccessTokenRequestOptions
): Promise<VerifyAccessTokenRequestReturn> {
  if (options.grant.preAuthorizedCode !== options.expectedPreAuthorizedCode) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidGrant,
      error_description: `Invalid 'pre-authorized_code' provided`,
    })
  }

  // If they do not match there is an error
  if (options.grant.txCode !== options.expectedTxCode) {
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

  if (options.pkce) {
    await verifyAccessTokenRequestPkce(options.pkce, options.callbacks)
  }

  const dpopResult = options.dpop
    ? await verifyAccessTokenRequestDpop(options.dpop, options.request, options.callbacks)
    : null

  return { dpopJwk: dpopResult?.dpopJwk }
}

export interface VerifyAuthorizationCodeAccessTokenRequestOptions {
  grant: ParsedAccessTokenAuthorizationCodeRequestGrant
  accessTokenRequest: AccessTokenRequest
  request: RequestLike

  expectedCode: string

  dpop?: VerifyAccessTokenRequestDpop
  pkce?: VerifyAccessTokenRequestPkce

  codeExpiresAt?: Date
  now?: Date

  callbacks: Pick<CallbackContext, 'hash' | 'verifyJwt'>
}

export async function verifyAuthorizationCodeAccessTokenRequest(
  options: VerifyAuthorizationCodeAccessTokenRequestOptions
): Promise<VerifyAccessTokenRequestReturn> {
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

  if (options.pkce) {
    await verifyAccessTokenRequestPkce(options.pkce, options.callbacks)
  }

  const dpopResult = options.dpop
    ? await verifyAccessTokenRequestDpop(options.dpop, options.request, options.callbacks)
    : null

  return { dpopJwk: dpopResult?.dpopJwk }
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

  if (!options.jwt) return null

  try {
    const { header } = await verifyDpopJwt({
      callbacks,
      dpopJwt: options.jwt,
      request,
      allowedSigningAlgs: options.allowedSigningAlgs,
    })

    return {
      dpopJwk: header.jwk,
    }
  } catch (error) {
    if (error instanceof Oauth2Error) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidDpopProof,
        error_description: error.message,
      })
    }
    throw error
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
