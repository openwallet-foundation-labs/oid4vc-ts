/**
 * Algorithm transformation utilities for JWA and COSE
 *
 * This module provides utilities to transform between JWA (JSON Web Algorithms)
 * signature algorithm identifiers and fully-specified COSE (CBOR Object Signing and Encryption)
 * algorithm identifiers.
 *
 * Based on RFC 9864: Fully-Specified Algorithms for JOSE and COSE
 * https://www.rfc-editor.org/rfc/rfc9864.html
 */

import { Oauth2Error } from '../../error/Oauth2Error'

/**
 * JWA (JSON Web Algorithms) signature algorithm identifiers
 *
 * From RFC 7518 (JWA) and RFC 9864 (Fully-Specified Algorithms)
 */
enum JwaSignatureAlgorithm {
  // EdDSA algorithms - RFC 9864 Section 2.2
  Ed25519 = 'Ed25519',
  Ed448 = 'Ed448',

  // Deprecated polymorphic EdDSA - RFC 9864 Section 4.1.2
  // Maps to Ed25519 as it's the most common use case (similar to WebAuthn's approach)
  EdDSA = 'EdDSA',

  // ECDSA algorithms - RFC 9864 Section 2.1
  // JWA ECDSA algorithms are already fully-specified
  ES256 = 'ES256',
  ES384 = 'ES384',
  ES512 = 'ES512',
  ES256K = 'ES256K',

  // RSA algorithms - RFC 7518
  RS256 = 'RS256',
  RS384 = 'RS384',
  RS512 = 'RS512',
  PS256 = 'PS256',
  PS384 = 'PS384',
  PS512 = 'PS512',
}

/**
 * Mapping of JWA signature algorithm identifiers to fully-specified COSE algorithm identifiers
 *
 * From RFC 9864:
 * - EdDSA algorithms (Section 2.2)
 * - ECDSA algorithms (Section 2.1) - JWA ECDSA algorithms are already fully-specified
 *
 * Note: JWA ECDSA algorithms (ES256, ES384, ES512) are already fully-specified,
 * while COSE ECDSA algorithms with the same names are polymorphic and deprecated.
 * The fully-specified COSE equivalents use different names (ESP256, ESP384, ESP512).
 */
const JWA_SIGNATURE_TO_COSE_ALGORITHM_MAP = {
  // EdDSA algorithms - RFC 9864 Section 2.2
  [JwaSignatureAlgorithm.Ed25519]: -19,
  [JwaSignatureAlgorithm.Ed448]: -53,

  // Deprecated polymorphic EdDSA - RFC 9864 Section 4.1.2
  // Maps to Ed25519 as it's the most common use case (similar to WebAuthn's approach)
  [JwaSignatureAlgorithm.EdDSA]: -19,

  // ECDSA algorithms - RFC 9864 Section 2.1
  // JOSE ES256/ES384/ES512 map to fully-specified COSE ESP256/ESP384/ESP512
  [JwaSignatureAlgorithm.ES256]: -9, // COSE ESP256 (ECDSA using P-256 curve and SHA-256)
  [JwaSignatureAlgorithm.ES384]: -51, // COSE ESP384 (ECDSA using P-384 curve and SHA-384)
  [JwaSignatureAlgorithm.ES512]: -52, // COSE ESP512 (ECDSA using P-521 curve and SHA-512)
  [JwaSignatureAlgorithm.ES256K]: -47, // ECDSA using secp256k1 curve and SHA-256

  // RSA algorithms - RFC 7518
  [JwaSignatureAlgorithm.RS256]: -257, // RSASSA-PKCS1-v1_5 using SHA-256
  [JwaSignatureAlgorithm.RS384]: -258, // RSASSA-PKCS1-v1_5 using SHA-384
  [JwaSignatureAlgorithm.RS512]: -259, // RSASSA-PKCS1-v1_5 using SHA-512
  [JwaSignatureAlgorithm.PS256]: -37, // RSASSA-PSS using SHA-256 and MGF1 with SHA-256
  [JwaSignatureAlgorithm.PS384]: -38, // RSASSA-PSS using SHA-384 and MGF1 with SHA-384
  [JwaSignatureAlgorithm.PS512]: -39, // RSASSA-PSS using SHA-512 and MGF1 with SHA-512
} as const

/**
 * Mapping of COSE algorithm identifiers to JWA signature algorithm identifiers
 *
 * This is the inverse of JWA_SIGNATURE_TO_COSE_ALGORITHM_MAP, with additional entries
 * for deprecated polymorphic COSE algorithms that should be avoided.
 */
const COSE_TO_JWA_SIGNATURE_ALGORITHM_MAP = {
  // EdDSA algorithms - RFC 9864 Section 2.2
  [-19]: JwaSignatureAlgorithm.Ed25519,
  [-53]: JwaSignatureAlgorithm.Ed448,

  // Deprecated polymorphic EdDSA - RFC 9864 Section 4.1.2 & 4.2.2
  // Maps to Ed25519 as it's the most common use case (similar to WebAuthn's approach)
  [-8]: JwaSignatureAlgorithm.Ed25519,

  // ECDSA algorithms - RFC 9864 Section 2.1
  // Fully-specified COSE algorithms
  [-9]: JwaSignatureAlgorithm.ES256, // ESP256 -> ES256
  [-51]: JwaSignatureAlgorithm.ES384, // ESP384 -> ES384
  [-52]: JwaSignatureAlgorithm.ES512, // ESP512 -> ES512
  [-47]: JwaSignatureAlgorithm.ES256K, // ECDSA using secp256k1

  // Deprecated polymorphic COSE ECDSA algorithms - RFC 9864 Section 4.2.2
  // These are included for backwards compatibility but should be avoided
  [-7]: JwaSignatureAlgorithm.ES256, // Deprecated COSE ES256 (polymorphic)
  [-35]: JwaSignatureAlgorithm.ES384, // Deprecated COSE ES384 (polymorphic)
  [-36]: JwaSignatureAlgorithm.ES512, // Deprecated COSE ES512 (polymorphic)

  // RSA algorithms
  [-257]: JwaSignatureAlgorithm.RS256,
  [-258]: JwaSignatureAlgorithm.RS384,
  [-259]: JwaSignatureAlgorithm.RS512,
  [-37]: JwaSignatureAlgorithm.PS256,
  [-38]: JwaSignatureAlgorithm.PS384,
  [-39]: JwaSignatureAlgorithm.PS512,
} as const

export type CoseAlgorithmIdentifier = keyof typeof COSE_TO_JWA_SIGNATURE_ALGORITHM_MAP
export type JwaSignatureAlgorithmIdentifier = `${JwaSignatureAlgorithm}`

/**
 * Transform a JWA signature algorithm identifier to an RFC 9864 fully-specified COSE algorithm identifier
 *
 * @param jwaAlg - JWA signature algorithm identifier (e.g., 'Ed25519', 'ES256')
 * @returns Fully-specified COSE algorithm identifier (e.g., -19, -9) or undefined if not mappable
 *
 * @example
 * ```typescript
 * const coseAlg = jwaSignatureAlgorithmToFullySpecifiedCoseAlgorithm('Ed25519') // Returns -19
 * const coseAlg = jwaSignatureAlgorithmToFullySpecifiedCoseAlgorithm('ES256')   // Returns -9 (ESP256)
 * ```
 */
export function jwaSignatureAlgorithmToFullySpecifiedCoseAlgorithm(
  jwaAlg: string
): CoseAlgorithmIdentifier | undefined {
  return JWA_SIGNATURE_TO_COSE_ALGORITHM_MAP[jwaAlg as JwaSignatureAlgorithm]
}

/**
 * Transform a COSE algorithm identifier (either RFC 9864 fully-specified, or polymorphic) to a JWA signature algorithm identifier
 *
 * @param coseAlg - COSE algorithm identifier (e.g., -19, -9)
 * @returns JWA signature algorithm identifier (e.g., 'Ed25519', 'ES256') or undefined if not mappable
 *
 * @example
 * ```typescript
 * const jwaAlg = fullySpecifiedCoseAlgorithmToJwaSignatureAlgorithm(-19) // Returns 'Ed25519'
 * const jwaAlg = fullySpecifiedCoseAlgorithmToJwaSignatureAlgorithm(-9)  // Returns 'ES256'
 * const jwaAlg = fullySpecifiedCoseAlgorithmToJwaSignatureAlgorithm(-7)  // Returns 'ES256' (deprecated polymorphic COSE ES256)
 * ```
 */
export function fullySpecifiedCoseAlgorithmToJwaSignatureAlgorithm(
  coseAlg: number
): JwaSignatureAlgorithmIdentifier | undefined {
  return COSE_TO_JWA_SIGNATURE_ALGORITHM_MAP[coseAlg as CoseAlgorithmIdentifier]
}

/**
 * Transform an array of JWA signature algorithm identifiers to RFC 9864 fully-specified COSE algorithm identifiers.
 *
 * By default it filters out unmappable algorithms. You can also choose to throw an error when an unknown
 * algorithm is detected.
 *
 * @param jwaAlgs - Array of JWA signature algorithm identifiers
 * @returns Array of fully-specified COSE algorithm identifiers
 *
 * @example
 * ```typescript
 * const coseAlgs = jwaSignatureAlgorithmArrayToFullySpecifiedCoseAlgorithmArray(['Ed25519', 'ES256', 'Unknown'])
 * // Returns [-19, -9]
 * ```
 */
export function jwaSignatureAlgorithmArrayToFullySpecifiedCoseAlgorithmArray(
  jwaAlgs: string[],
  throwOnUnknownValue = false
): CoseAlgorithmIdentifier[] {
  return jwaAlgs
    .map((jwaAlg) => {
      const coseAlg = jwaSignatureAlgorithmToFullySpecifiedCoseAlgorithm(jwaAlg)
      if (coseAlg || !throwOnUnknownValue) return coseAlg
      throw new Oauth2Error(`Found unknown JWA signature algorithm '${jwaAlg}'. Unable to map to COSE algorithm.`)
    })
    .filter((coseAlg): coseAlg is CoseAlgorithmIdentifier => coseAlg !== undefined)
}

/**
 * Transform an array of COSE algorithm identifiers (either RFC 9864 fully-specified or polymorphic) to JWA signature algorithm identifiers
 *
 * By default it filters out unmappable algorithms. You can also choose to throw an error when an unknown
 * algorithm is detected.
 *
 * @param coseAlgs - Array of COSE algorithm identifiers
 * @returns Array of JWA signature algorithm identifiers
 *
 * @example
 * ```typescript
 * const jwaAlgs = fullySpecifiedCoseAlgorithmArrayToJwaSignatureAlgorithmArray([-19, -9, 999])
 * // Returns ['Ed25519', 'ES256']
 * ```
 */
export function fullySpecifiedCoseAlgorithmArrayToJwaSignatureAlgorithmArray(
  coseAlgs: number[],
  throwOnUnknownValue = false
): JwaSignatureAlgorithmIdentifier[] {
  return coseAlgs
    .map((coseAlg) => {
      const jwaAlg = fullySpecifiedCoseAlgorithmToJwaSignatureAlgorithm(coseAlg)
      if (jwaAlg || !throwOnUnknownValue) return jwaAlg
      throw new Oauth2Error(
        `Found unknown COSE algorithm identifier '${coseAlg}'. Unable to map to JWA signature algorithm.`
      )
    })
    .filter((alg): alg is JwaSignatureAlgorithmIdentifier => alg !== undefined)
}
