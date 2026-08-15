import {
  ContentType,
  createZodFetcher,
  type Fetch,
  InvalidFetchResponseError,
  parseWithErrorHandling,
} from '@openid4vc/utils'
import { ValidationError } from '../../../utils/src/error/ValidationError'
import type { CallbackContext } from '../callbacks'
import { type JwkSet, zJwkSet } from '../common/jwk/z-jwk'

/**
 * Fetch JWKs from a provided JWKs URI.
 *
 * If a `getJwks` callback is provided and returns a JWK Set for the `jwksUrl`, that JWK Set is
 * returned and no request is performed.
 *
 * Returns validated metadata if successful response
 * Throws error otherwise
 *
 * @throws {ValidationError} if successful response but validation of response failed
 * @throws {InvalidFetchResponseError} if unsuccessful response
 */
export async function fetchJwks(
  jwksUrl: string,
  fetchOrCallbacks?: Fetch | Pick<CallbackContext, 'fetch' | 'getJwks'>
): Promise<JwkSet> {
  const callbacks = typeof fetchOrCallbacks === 'function' ? { fetch: fetchOrCallbacks } : fetchOrCallbacks
  const providedJwks = await callbacks?.getJwks?.(jwksUrl)
  if (providedJwks) {
    // Validated the same way as JWKs retrieved from the jwks_uri
    return parseWithErrorHandling(
      zJwkSet,
      providedJwks,
      `Validation of JWKs provided by the 'getJwks' callback for jwks_uri '${jwksUrl}' failed`
    )
  }

  const fetcher = createZodFetcher(callbacks?.fetch)

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
