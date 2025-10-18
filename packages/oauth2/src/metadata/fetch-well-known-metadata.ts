import { type BaseSchema, ContentType, createZodFetcher, type Fetch, InvalidFetchResponseError } from '@openid4vc/utils'
import type z from 'zod'
import { ValidationError } from '../../../utils/src/error/ValidationError'

export interface FetchWellKnownMetadataOptions {
  /**
   * Custom fetch implementation to use for fetching the metadata
   */
  fetch?: Fetch

  /**
   * The accepted content types. If not provided a default of `ContentType.Json`
   * will be used. This will be used for the `Accept` header, as well as verified
   * against the `Content-Type` response header.
   */
  acceptedContentType?: [ContentType, ...ContentType[]]
}

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
  options?: FetchWellKnownMetadataOptions
): Promise<z.infer<Schema> | null> {
  const fetcher = createZodFetcher(options?.fetch)

  const acceptedContentType = options?.acceptedContentType ?? [ContentType.Json]

  const { result, response } = await fetcher(schema, acceptedContentType, wellKnownMetadataUrl)
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
