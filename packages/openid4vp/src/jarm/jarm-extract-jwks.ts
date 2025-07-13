import type { JwkSet } from '@openid4vc/oauth2'

export function extractEncryptionJwkFromJwks(
  jwks: JwkSet,
  {
    kid,
    supportedAlgValues,
  }: {
    kid?: string
    supportedAlgValues?: string[]
  }
) {
  if (kid) {
    return jwks.keys.find((jwk) => jwk.kid === kid)
  }

  let algFiltered = jwks.keys.filter((key) => key.alg && supportedAlgValues?.includes(key.alg))
  if (algFiltered.length === 0) algFiltered = jwks.keys

  let encFiltered = algFiltered.filter((key) => key.use === 'enc')
  if (!encFiltered) encFiltered = algFiltered.filter((key) => key.use !== 'sig')

  return encFiltered.length > 0 ? encFiltered[0] : jwks.keys[0]
}
