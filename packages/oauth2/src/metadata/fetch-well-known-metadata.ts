import { type BaseSchema, ContentType, createZodFetcher, type Fetch, InvalidFetchResponseError } from '@openid4vc/utils'
import type z from 'zod'
import { ValidationError } from '../../../utils/src/error/ValidationError'

/**
 * Fetch well known metadata and validate the response.
 *
 * Returns null if 404 is returned
 * Returns validated metadata if successful response
 * Throws error otherwise
 *
 * @throws {ValidationError} if successful response but validation of response failed
 * @throws {InvalidFetchResponseError} if no successful or 404 response
 * @throws {Error} if parsing json from response fails
 */
export async function fetchWellKnownMetadata<Schema extends BaseSchema>(
  wellKnownMetadataUrl: string,
  schema: Schema,
  fetch?: Fetch
): Promise<z.infer<Schema> | null> {
  const fetcher = createZodFetcher(fetch)

  const { result, response } = await fetcher(schema, ContentType.Json, wellKnownMetadataUrl)
  if (response.status === 404) {
    return null
  }

  if (!response.ok) {
    throw new InvalidFetchResponseError(
      `Fetching well known metadata from '${wellKnownMetadataUrl}' resulted in an unsuccessful response with status '${response.status}'.`,
      await response.clone().text(),
      response
    )
  }

  if (!result?.success) {
    throw new ValidationError(`Validation of metadata from '${wellKnownMetadataUrl}' failed`, result?.error)
  }

  return result.data
}
