import { HashAlgorithm, type HashCallback } from '../callbacks'
import { decodeUtf8StringToUint8Array, encodeUint8ArrayToBase64Url } from '../common/encoding'
import { Oid4vcError } from '../error/Oid4vcError'

export enum PkceCodeChallengeMethod {
  Plain = 'plain',
  S256 = 'S256',
}

export interface CreatePkceOptions {
  /**
   * secure random code verifier
   */
  codeVerifier: string

  /**
   * Also allows string values so it can be directly passed from the
   * 'code_challenge_methods_supported' metadata parameter
   */
  allowedCodeChallengeMethods?: Array<string | PkceCodeChallengeMethod>

  /**
   * Hashing callback, used to generate the code challenge
   */
  hashCallback?: HashCallback
}

export async function createPkce(options: CreatePkceOptions) {
  const allowedCodeChallengeMethods = options.allowedCodeChallengeMethods ?? [
    PkceCodeChallengeMethod.S256,
    PkceCodeChallengeMethod.Plain,
  ]

  if (allowedCodeChallengeMethods.length === 0) {
    throw new Oid4vcError(`Unable to create PKCE code verifier. 'allowedCodeChallengeMethods' is an empty array.`)
  }

  if (!options.hashCallback && !allowedCodeChallengeMethods.includes(PkceCodeChallengeMethod.Plain)) {
    throw new Oid4vcError(
      `No 'hashCallback' provided in 'createPkce' method, and code challenge method '${PkceCodeChallengeMethod.Plain} is not supported`
    )
  }

  const codeChallengeMethod =
    options.hashCallback && allowedCodeChallengeMethods.includes(PkceCodeChallengeMethod.S256)
      ? PkceCodeChallengeMethod.S256
      : PkceCodeChallengeMethod.Plain

  return {
    codeChallenge: await calculateCodeChallenge({
      codeChallengeMethod,
      codeVerifier: options.codeVerifier,
      hashCallback: options.hashCallback,
    }),
    codeChallengeMethod,
  }
}

export interface VerifyPkceOptions {
  /**
   * secure random code verifier
   */
  codeVerifier: string

  codeChallenge: string
  codeChallengeMethod: PkceCodeChallengeMethod

  /**
   * Hashing callback, used to generate the code challenge
   */
  hashCallback?: HashCallback
}

export async function verifyPkce(options: VerifyPkceOptions) {
  if (!options.hashCallback && options.codeChallengeMethod === PkceCodeChallengeMethod.S256) {
    throw new Oid4vcError(
      `No 'hashCallback' provided in 'verifyPkce' method, and code challenge method is '${PkceCodeChallengeMethod.S256}`
    )
  }

  const calculatedCodeChallenge = await calculateCodeChallenge({
    codeChallengeMethod: options.codeChallengeMethod,
    codeVerifier: options.codeVerifier,
    hashCallback: options.hashCallback,
  })

  if (options.codeChallenge !== calculatedCodeChallenge) {
    throw new Oid4vcError(
      `Received code challenge '${options.codeChallenge}' does not match the calculated code challenge '${calculatedCodeChallenge}' derived from code verifier ${options.codeVerifier} using method '${options.codeChallengeMethod}'.`
    )
  }
}

async function calculateCodeChallenge(options: {
  codeVerifier: string
  codeChallengeMethod: PkceCodeChallengeMethod
  hashCallback?: HashCallback
}) {
  if (options.codeChallengeMethod === PkceCodeChallengeMethod.Plain) {
    return options.codeVerifier
  }

  if (options.codeChallengeMethod === PkceCodeChallengeMethod.S256) {
    if (!options.hashCallback) {
      throw new Oid4vcError(`No 'hashCallback' provided and code challenge method is '${PkceCodeChallengeMethod.S256}.`)
    }

    return encodeUint8ArrayToBase64Url(
      await options.hashCallback(decodeUtf8StringToUint8Array(options.codeVerifier), HashAlgorithm.Sha256)
    )
  }
}
