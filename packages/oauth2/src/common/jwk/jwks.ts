import { type CallbackContext, HashAlgorithm } from '../../callbacks'
import { Oauth2Error } from '../../error/Oauth2Error'
import { calculateJwkThumbprint } from './jwk-thumbprint'
import type { Jwk, JwkSet } from './z-jwk'

interface ExtractJwkFromJwksForJwtOptions {
  kid?: string
  use: 'enc' | 'sig'

  /**
   * The JWKs
   */
  jwks: JwkSet
}

/**
 *
 * @param header
 * @param jwks
 */
export function extractJwkFromJwksForJwt(options: ExtractJwkFromJwksForJwtOptions) {
  const jwksForUse = options.jwks.keys.filter(({ use }) => !use || use === options.use)
  const jwkForKid = options.kid ? jwksForUse.find(({ kid }) => kid === options.kid) : undefined

  if (jwkForKid) {
    return jwkForKid
  }

  if (jwksForUse.length === 1) {
    return jwksForUse[0]
  }

  throw new Oauth2Error(
    `Unable to extract jwk from jwks for use '${options.use}'${options.kid ? `with kid '${options.kid}'.` : '. No kid provided and more than jwk.'}`
  )
}

export async function isJwkInSet({
  jwk,
  jwks,
  callbacks,
}: {
  jwk: Jwk
  jwks: Jwk[]
  callbacks: Pick<CallbackContext, 'hash'>
}) {
  const jwkThumbprint = await calculateJwkThumbprint({
    hashAlgorithm: HashAlgorithm.Sha256,
    hashCallback: callbacks.hash,
    jwk,
  })

  for (const jwkFromSet of jwks) {
    const jwkFromSetThumbprint = await calculateJwkThumbprint({
      hashAlgorithm: HashAlgorithm.Sha256,
      hashCallback: callbacks.hash,
      jwk: jwkFromSet,
    })

    if (jwkFromSetThumbprint === jwkThumbprint) return true
  }

  return false
}
