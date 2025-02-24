import type { Fetch, OrPromise } from '@openid4vc/utils'
import type { ClientAuthenticationCallback } from './client-authentication'
import type { Jwk } from './common/jwk/z-jwk'
import type { JweEncryptor, JwtHeader, JwtPayload, JwtSigner } from './common/jwt/z-jwt'

/**
 * Supported hashing algorithms
 */
export enum HashAlgorithm {
  Sha256 = 'SHA-256',
}

/**
 * Callback used for operations that require hashing
 */
export type HashCallback = (data: Uint8Array, alg: HashAlgorithm) => OrPromise<Uint8Array>

export type GenerateRandomCallback = (byteLength: number) => OrPromise<Uint8Array>

export type SignJwtCallback = (
  jwtSigner: JwtSigner,
  jwt: { header: JwtHeader; payload: JwtPayload }
) => OrPromise<{
  jwt: string
  signerJwk: Jwk
}>

export type VerifyJwtCallback = (
  jwtSigner: JwtSigner,
  jwt: { header: JwtHeader; payload: JwtPayload; compact: string }
) => OrPromise<
  | {
      verified: true
      signerJwk: Jwk
    }
  | {
      verified: false
      signerJwk?: Jwk
    }
>

export interface DecryptJweCallbackOptions {
  jwk: Jwk
}

export type DecryptJweCallback = (
  jwe: string,
  options?: DecryptJweCallbackOptions
) => OrPromise<
  | {
      decrypted: true
      decryptionJwk: Jwk
      payload: string
    }
  | {
      decrypted: false
      decryptionJwk?: Jwk
      payload?: string
    }
>

export type EncryptJweCallback = (
  jweEncryptor: JweEncryptor,
  data: string
) => OrPromise<{
  encryptionJwk: Jwk
  jwe: string
}>

/**
 * Callback context provides the callbacks that are required for the openid4vc library
 */
export interface CallbackContext {
  /**
   * Custom fetch implementation to use
   */
  fetch?: Fetch

  /**
   * Hash callback used for e.g. dpop and pkce
   */
  hash: HashCallback

  /**
   * Sign jwt callback for signing of Json Web Tokens
   */
  signJwt: SignJwtCallback

  /**
   * Decrypt jwe callback for decrypting of Json Web Encryptions
   */
  decryptJwe: DecryptJweCallback

  /**
   * Encrypt jwt callback for encrypting of Json Web Encryptions
   */
  encryptJwe: EncryptJweCallback

  /**
   * Verify jwt callback for verification of Json Web Tokens
   */
  verifyJwt: VerifyJwtCallback

  /**
   * Generate random callback to generate random bytes. Used for
   * e.g. the 'jti' value in a dpop jwt, and 'code_verifier' in pkce.
   */
  generateRandom: GenerateRandomCallback

  /**
   * Extend a request to the authorization server with client authentication
   * parameters. If you're not using client authentication, you can set this
   * to `clientAuthenticationNone()`
   *
   * There are three default client authentication methods provided:
   * - `clientAuthenticationClientSecretPost`
   * - `clientAuthenticationClientSecretBasic`
   * - `clientAuthenticationNone`
   *
   * A custom implementation can be made for other methods, or allowing complex
   * scenarios where multiple authorization servers are supported.
   */
  clientAuthentication: ClientAuthenticationCallback

  /**
   * Get the DNS names and URI names from a X.509 certificate
   */
  getX509CertificateMetadata?: (certificate: string) => {
    sanDnsNames: string[]
    sanUriNames: string[]
  }
}
