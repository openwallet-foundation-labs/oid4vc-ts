import { type BaseSchema, type Fetch, createValibotFetcher } from '@animo-id/oid4vc-utils'
import type * as v from 'valibot'
import { ValidationError } from '../../../utils/src/error/ValidationError'
import { Oauth2InvalidFetchResponseError } from '../error/Oauth2InvalidFetchResponseError'

/**
 * Fetch well known metadata and validate the response.
 *
 * Returns null if 404 is returned
 * Returns validated metadata if successfull response
 * Throws error otherwise
 *
 * @throws {ValidationError} if successfull response but validation of response failed
 * @throws {Oauth2InvalidFetchResponseError} if no successfull or 404 response
 * @throws {Error} if parsing json from response fails
 */
export async function fetchWellKnownMetadata<Schema extends BaseSchema>(
  wellKnownMetadataUrl: string,
  schema: Schema,
  fetch?: Fetch
): Promise<v.InferOutput<Schema> | null> {
  const fetcher = createValibotFetcher(fetch)

  const { result, response } = await fetcher(schema, wellKnownMetadataUrl)
  if (response.status === 404) {
    return null
  }

  if (!response.ok) {
    throw new Oauth2InvalidFetchResponseError(
      `Fetching well known metadata from '${wellKnownMetadataUrl}' did resulted in an unsuccessfull response with status '${response.status}'.`,
      await response.clone().text(),
      response
    )
  }

  if (!result || !result.success) {
    throw new ValidationError(`Validation of metadata from '${wellKnownMetadataUrl}' failed`, result?.issues)
  }

  return result.output
}
