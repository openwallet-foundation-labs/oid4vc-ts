import { dateToSeconds } from '@openid4vc/utils'
import type { VerifyJwtCallback } from '../../callbacks'
import { Oauth2JwtVerificationError } from '../../error/Oauth2JwtVerificationError'
import type { Jwk } from '../jwk/z-jwk'
import type { JwtHeader, JwtPayload, JwtSigner, JwtSignerWithJwk } from './z-jwt'

export interface VerifyJwtOptions {
  /**
   * Compact jwt
   */
  compact: string

  /**
   * Header of the jwt
   */
  header: JwtHeader

  /**
   * Payload of the jwt.
   */
  payload: JwtPayload

  /**
   * If not provided current time will be used.
   *
   * @default new Date()
   */
  now?: Date

  /**
   * Whether to skip time based validation of `nbf` and `exp`.
   * @default false
   */
  skipTimeBasedValidation?: boolean

  /**
   * Callback to verify jwt signature
   */
  verifyJwtCallback: VerifyJwtCallback

  /**
   * Signer of the jwt
   */
  signer: JwtSigner

  /**
   * Custom error message
   */
  errorMessage?: string

  /**
   * Allowed skew time in seconds for validity of token. Used for `exp` and `nbf`
   * verification.
   *
   * @default 0
   */
  allowedSkewInSeconds?: number

  /**
   * Expected value for the 'aud' claim
   */
  expectedAudience?: string

  /**
   * Expected value for the 'iss' claim
   */
  expectedIssuer?: string

  /**
   * Expected value for the 'nonce' claim
   */
  expectedNonce?: string

  /**
   * Expected value for the 'sub' claim
   */
  expectedSubject?: string

  /**
   * The claims that are required to be present in the jwt.
   */
  requiredClaims?: string[]
}

export interface VerifyJwtReturn {
  signer: JwtSignerWithJwk
}

export async function verifyJwt(options: VerifyJwtOptions): Promise<VerifyJwtReturn> {
  const errorMessage = options.errorMessage ?? 'Error during verification of jwt.'

  let signerJwk: Jwk
  try {
    const result = await options.verifyJwtCallback(options.signer, {
      header: options.header,
      payload: options.payload,
      compact: options.compact,
    })

    if (!result.verified) throw new Oauth2JwtVerificationError(errorMessage)
    signerJwk = result.signerJwk
  } catch (error) {
    if (error instanceof Oauth2JwtVerificationError) throw error
    throw new Oauth2JwtVerificationError(errorMessage, { cause: error })
  }

  const nowInSeconds = dateToSeconds(options.now ?? new Date())
  const skewInSeconds = options.allowedSkewInSeconds ?? 0
  const timeBasedValidation = options.skipTimeBasedValidation !== undefined ? !options.skipTimeBasedValidation : true

  if (timeBasedValidation && options.payload.nbf && nowInSeconds < options.payload.nbf - skewInSeconds) {
    throw new Oauth2JwtVerificationError(`${errorMessage} jwt 'nbf' is in the future`)
  }

  if (timeBasedValidation && options.payload.exp && nowInSeconds > options.payload.exp + skewInSeconds) {
    throw new Oauth2JwtVerificationError(`${errorMessage} jwt 'exp' is in the past`)
  }

  if (options.expectedAudience) {
    if (
      (Array.isArray(options.payload.aud) && !options.payload.aud.includes(options.expectedAudience)) ||
      (typeof options.payload.aud === 'string' && options.payload.aud !== options.expectedAudience)
    ) {
      throw new Oauth2JwtVerificationError(`${errorMessage} jwt 'aud' does not match expected value.`)
    }
  }

  if (options.expectedIssuer && options.expectedIssuer !== options.payload.iss) {
    throw new Oauth2JwtVerificationError(`${errorMessage} jwt 'iss' does not match expected value.`)
  }

  if (options.expectedNonce && options.expectedNonce !== options.payload.nonce) {
    throw new Oauth2JwtVerificationError(`${errorMessage} jwt 'nonce' does not match expected value.`)
  }

  if (options.expectedSubject && options.expectedSubject !== options.payload.sub) {
    throw new Oauth2JwtVerificationError(`${errorMessage} jwt 'sub' does not match expected value.`)
  }

  if (options.requiredClaims) {
    for (const claim of options.requiredClaims) {
      if (!options.payload[claim]) {
        throw new Oauth2JwtVerificationError(`${errorMessage} jwt '${claim}' is missing.`)
      }
    }
  }

  return {
    signer: {
      ...options.signer,
      publicJwk: signerJwk,
    },
  }
}
