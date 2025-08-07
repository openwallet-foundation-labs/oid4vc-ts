import { ContentType, type Fetch, createZodFetcher } from '@openid4vc/utils'
import { InvalidFetchResponseError } from '@openid4vc/utils'
import { ValidationError } from '../../../utils/src/error/ValidationError'
import { type JwkSet, zJwkSet } from '../common/jwk/z-jwk'

/**
 * Fetch JWKs from a provided JWKs URI.
 *
 * Returns validated metadata if successful response
 * Throws error otherwise
 *
 * @throws {ValidationError} if successful response but validation of response failed
 * @throws {InvalidFetchResponseError} if unsuccesful response
 */
export async function fetchJwks(jwksUrl: string, fetch?: Fetch): Promise<JwkSet> {
  const fetcher = createZodFetcher(fetch)

  const { result, response } = await fetcher(zJwkSet, [ContentType.JwkSet, ContentType.Json], jwksUrl)
  if (!response.ok) {
    throw new InvalidFetchResponseError(
      `Fetching JWKs from jwks_uri '${jwksUrl}' resulted in an unsuccessful response with status code '${response.status}'.`,
      await response.clone().text(),
      response
    )
  }

  if (!result?.success) {
    throw new ValidationError(`Validation of JWKs from jwks_uri '${jwksUrl}' failed`, result?.error)
  }

  return result.data
}
