import { Oauth2Error } from '../../error/Oauth2Error'
import type { JwkSet } from './v-jwk'

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
