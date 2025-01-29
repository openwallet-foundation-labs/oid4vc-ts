import { ContentType, createZodFetcher, type Fetch } from '@openid4vc/utils'
import { InvalidFetchResponseError } from '@openid4vc/utils'
import { ValidationError } from '../../../utils/src/error/ValidationError'
import { type JwkSet, vJwkSet } from '../common/jwk/v-jwk'
import { Oauth2Error } from '../error/Oauth2Error'
import type { AuthorizationServerMetadata } from './authorization-server/v-authorization-server-metadata'

/**
 * Fetch JWKs from jwks_uri in authorization server metadata
 *
 * Returns null if 404 is returned
 * Returns validated metadata if successfull response
 * Throws error otherwise
 *
 * @throws {ValidationError} if successfull response but validation of response failed
 * @throws {InvalidFetchResponseError} if unsuccesful response
 * @throws {Oauth2Error} if authorization server does not have a jwks_uri
 */
export async function fetchJwks(authorizationServer: AuthorizationServerMetadata, fetch?: Fetch): Promise<JwkSet> {
  const fetcher = createZodFetcher(fetch)

  const jwksUrl = authorizationServer.jwks_uri
  if (!jwksUrl) {
    throw new Oauth2Error(
      `Authorization server '${authorizationServer.issuer}' does not have a 'jwks_uri' parameter to fetch JWKs.`
    )
  }

  const { result, response } = await fetcher(vJwkSet, ContentType.JwkSet, jwksUrl)
  if (!response.ok) {
    throw new InvalidFetchResponseError(
      `Fetching JWKs from jwks_uri '${jwksUrl}' resulted in an unsuccessfull response with status code '${response.status}'.`,
      await response.clone().text(),
      response
    )
  }

  if (!result || !result.success) {
    throw new ValidationError(`Validation of JWKs from jwks_uri '${jwksUrl}' failed`, result?.error.issues)
  }

  return result.data
}
