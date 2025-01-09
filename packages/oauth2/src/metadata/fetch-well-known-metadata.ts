import { type BaseSchema, ContentType, type Fetch, createValibotFetcher } from '@openid4vc/utils'
import { InvalidFetchResponseError } from '@openid4vc/utils'
import type * as v from 'valibot'
import { ValidationError } from '../../../utils/src/error/ValidationError'

/**
 * Fetch well known metadata and validate the response.
 *
 * Returns null if 404 is returned
 * Returns validated metadata if successfull response
 * Throws error otherwise
 *
 * @throws {ValidationError} if successfull response but validation of response failed
 * @throws {InvalidFetchResponseError} if no successfull or 404 response
 * @throws {Error} if parsing json from response fails
 */
export async function fetchWellKnownMetadata<Schema extends BaseSchema>(
  wellKnownMetadataUrl: string,
  schema: Schema,
  fetch?: Fetch
): Promise<v.InferOutput<Schema> | null> {
  const fetcher = createValibotFetcher(fetch)

  const { result, response } = await fetcher(schema, ContentType.Json, wellKnownMetadataUrl)
  if (response.status === 404) {
    return null
  }

  if (!response.ok) {
    throw new InvalidFetchResponseError(
      `Fetching well known metadata from '${wellKnownMetadataUrl}' resulted in an unsuccessfull response with status '${response.status}'.`,
      await response.clone().text(),
      response
    )
  }

  if (!result || !result.success) {
    throw new ValidationError(`Validation of metadata from '${wellKnownMetadataUrl}' failed`, result?.issues)
  }

  return result.output
}
