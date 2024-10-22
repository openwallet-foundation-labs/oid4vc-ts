import type * as v from 'valibot'
import type { BaseSchema } from '../common/validation/v-common'
import { Oid4vcValidationError } from '../error/Oid4vcValidationError'
import { type Fetch, createValibotFetcher } from '../utils/valibot-fetcher'

/**
 * Fetch well known metadata and validate the response.
 *
 * Returns null if 404 is returned
 * Returns validated metadata if successfull response
 * Throws error otherwise
 *
 * @throws {Oid4vcValidationError} if successfull response but validation of response failed
 * @throws {Error} if no successfull or 404 response
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
    throw new Error(
      `Fetching well known metadata from '${wellKnownMetadataUrl}' did not result in a successfull or not found response.`
    )
  }

  if (!result || !result.success) {
    throw new Oid4vcValidationError(`Validation of metadata from '${wellKnownMetadataUrl}' failed`, result?.issues)
  }

  return result.output
}
