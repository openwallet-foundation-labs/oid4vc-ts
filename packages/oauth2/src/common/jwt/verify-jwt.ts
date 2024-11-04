import { dateToSeconds } from '@animo-id/oauth2-utils'
import type { VerifyJwtCallback } from '../../callbacks'
import { Oauth2JwtVerificationError } from '../../error/Oauth2JwtVerificationError'
import type { JwtHeader, JwtPayload, JwtSigner } from './v-jwt'

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
}

export async function verifyJwt(options: VerifyJwtOptions) {
  const errorMessage = options.errorMessage ?? 'Error during verification of jwt.'
  try {
    const isValid = await options.verifyJwtCallback(options.signer, {
      header: options.header,
      payload: options.payload,
      compact: options.compact,
    })

    if (!isValid) throw new Oauth2JwtVerificationError(errorMessage)
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

  if (options.expectedAudience && options.expectedAudience !== options.payload.aud) {
    throw new Oauth2JwtVerificationError(`${errorMessage} jwt 'aud' does not match expected value.`)
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
}
