/**
 * Supported hashing algorithms
 */
export enum HashAlgorithm {
  Sha256 = 'SHA-256',
}

/**
 * Callback used for operations that require hashing
 */
export type HashCallback = (data: Uint8Array, alg: HashAlgorithm) => Promise<Uint8Array> | Uint8Array

export type GenerateRandomCallback = (length: number) => Uint8Array
