import { type CallbackContext, HashAlgorithm, type HashCallback } from '../callbacks'
import { decodeUtf8String, encodeToBase64Url } from '../common/encoding'
import { Oid4vcError } from '../error/Oid4vcError'

export enum PkceCodeChallengeMethod {
  Plain = 'plain',
  S256 = 'S256',
}

export interface CreatePkceOptions {
  /**
   * Also allows string values so it can be directly passed from the
   * 'code_challenge_methods_supported' metadata parameter
   */
  allowedCodeChallengeMethods?: Array<string | PkceCodeChallengeMethod>

  /**
   * Code verifier to use. If not provided a value will be generated.
   */
  codeVerifier?: string

  callbacks: Pick<CallbackContext, 'hash' | 'generateRandom'>
}

export async function createPkce(options: CreatePkceOptions) {
  const allowedCodeChallengeMethods = options.allowedCodeChallengeMethods ?? [
    PkceCodeChallengeMethod.S256,
    PkceCodeChallengeMethod.Plain,
  ]

  if (allowedCodeChallengeMethods.length === 0) {
    throw new Oid4vcError(`Unable to create PKCE code verifier. 'allowedCodeChallengeMethods' is an empty array.`)
  }

  const codeChallengeMethod = allowedCodeChallengeMethods.includes(PkceCodeChallengeMethod.S256)
    ? PkceCodeChallengeMethod.S256
    : PkceCodeChallengeMethod.Plain

  const codeVerifier = options.codeVerifier ?? encodeToBase64Url(await options.callbacks.generateRandom(64))
  return {
    codeVerifier,
    codeChallenge: await calculateCodeChallenge({
      codeChallengeMethod,
      codeVerifier,
      hashCallback: options.callbacks.hash,
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

  callbacks: Pick<CallbackContext, 'hash'>
}

export async function verifyPkce(options: VerifyPkceOptions) {
  const calculatedCodeChallenge = await calculateCodeChallenge({
    codeChallengeMethod: options.codeChallengeMethod,
    codeVerifier: options.codeVerifier,
    hashCallback: options.callbacks.hash,
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
  hashCallback: HashCallback
}) {
  if (options.codeChallengeMethod === PkceCodeChallengeMethod.Plain) {
    return options.codeVerifier
  }

  if (options.codeChallengeMethod === PkceCodeChallengeMethod.S256) {
    return encodeToBase64Url(await options.hashCallback(decodeUtf8String(options.codeVerifier), HashAlgorithm.Sha256))
  }
}
