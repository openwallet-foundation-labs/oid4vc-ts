import type { Fetch, OrPromise } from '@openid4vc/utils'
import type { ClientAuthenticationCallback } from './client-authentication'
import type { Jwk, JwkSet } from './common/jwk/z-jwk'
import type { JweEncryptor, JwtHeader, JwtPayload, JwtSigner } from './common/jwt/z-jwt'
import type { AuthorizationServerMetadata } from './metadata/authorization-server/z-authorization-server-metadata'

/**
 * Supported hashing algorithms
 *
 * Based on https://www.iana.org/assignments/named-information/named-information.xhtml
 */
export enum HashAlgorithm {
  Sha256 = 'sha-256',
  Sha384 = 'sha-384',
  Sha512 = 'sha-512',
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

export type VerifyDataIntegrityProofCallback = (
  dataIntegrityProof: Record<string, unknown>,
  document: Record<string, unknown>
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
  jwk?: Jwk
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

/**
 * Callback to resolve authorization server metadata without fetching it from the well-known
 * endpoints of the authorization server.
 *
 * The return value determines what happens next:
 * - metadata: used as-is, no request is performed.
 * - `undefined`: falls back to fetching the metadata over HTTP.
 * - `null`: the metadata definitively does not exist. No request is performed and the caller is
 *   told the metadata was not found. Return this instead of `undefined` when the callback already
 *   performed its own lookup, so the metadata is not requested a second time.
 *
 * The returned metadata is validated against the authorization server metadata schema and its
 * `issuer` MUST match the requested issuer, exactly as for fetched metadata. What the library
 * cannot check is where the metadata came from: it is used in place of the metadata that would
 * have been retrieved from the authorization server, so it MUST be at least as trustworthy. Only
 * return metadata you control (e.g. an authorization server hosted by this same application) or
 * metadata from a cache that you populated from a previous fetch for the same issuer.
 */
export type GetAuthorizationServerMetadataCallback = (
  issuer: string
) => OrPromise<AuthorizationServerMetadata | undefined | null>

/**
 * Callback to resolve a JWK Set without fetching it from the `jwks_uri`.
 *
 * Return `undefined` to fall back to fetching the JWK Set over HTTP.
 *
 * The returned JWK Set is validated against the JWK Set schema, exactly as for a fetched JWK Set.
 * What the library cannot check is where the keys came from: they are used to verify signatures in
 * place of the JWK Set that would have been fetched from `jwksUri`, so they MUST be at least as
 * trustworthy. Only return keys you control (e.g. the signing keys of an authorization server
 * hosted by this same application) or keys from a cache that you populated from a previous fetch
 * of the same `jwksUri`. Returning keys for a `jwksUri` you do not control allows arbitrary
 * signatures to be accepted.
 */
export type GetJwksCallback = (jwksUri: string) => OrPromise<JwkSet | undefined>

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
   * Optional callback to resolve authorization server metadata without performing a well-known
   * request. Useful to avoid network requests for authorization servers hosted by this same
   * application, or to serve metadata from a cache.
   *
   * If not provided, or if it returns `undefined`, the metadata is fetched over HTTP.
   */
  getAuthorizationServerMetadata?: GetAuthorizationServerMetadataCallback

  /**
   * Optional callback to resolve a JWK Set without performing a request to the `jwks_uri`. Useful
   * to avoid network requests for keys held by this same application, or to serve a JWK Set from a
   * cache.
   *
   * If not provided, or if it returns `undefined`, the JWK Set is fetched over HTTP.
   */
  getJwks?: GetJwksCallback

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
   * Verify a Data Integrity proof (e.g. the `proof` of a `di_vp` key proof's Verifiable
   * Presentation). Optional because most issuers won't support the `di_vp` proof type.
   */
  verifyDataIntegrityProof?: VerifyDataIntegrityProofCallback

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
   * - `clientAuthenticationClientAttestationJwt`
   * - `clientAuthenticationNone`
   * - `clientAuthenticationAnonymous`
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
