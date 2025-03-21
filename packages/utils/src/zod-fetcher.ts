import type z from 'zod'
import { ContentType, isResponseContentType } from './content-type'
import { FetchError } from './error/FetchError'
import { InvalidFetchResponseError } from './error/InvalidFetchResponseError'
import type { Fetch } from './globals'

/**
 * A type utility which represents the function returned
 * from createZodFetcher
 */
export type ZodFetcher = <Schema extends z.ZodTypeAny>(
  schema: Schema,
  expectedContentType: ContentType,
  ...args: Parameters<Fetch>
) => Promise<{ response: Awaited<ReturnType<Fetch>>; result?: z.SafeParseReturnType<Schema, z.infer<Schema>> }>

/**
 * The default fetcher used by createZodFetcher when no
 * fetcher is provided.
 */

// biome-ignore lint/style/noRestrictedGlobals: <explanation>
export const defaultFetcher = fetch

/**
 * Creates a `fetchWithZod` function that takes in a schema of
 * the expected response, and the arguments to the fetcher
 * you provided.
 *
 * @example
 *
 * const fetchWithZod = createZodFetcher((url) => {
 *   return fetch(url).then((res) => res.json());
 * });
 *
 * const response = await fetchWithZod(
 *   z.object({
 *     hello: z.string(),
 *   }),
 *   "https://example.com",
 * );
 */
export function createZodFetcher(fetcher = defaultFetcher): ZodFetcher {
  return async (schema, expectedContentType, ...args) => {
    const response = await fetcher(...args).catch((error) => {
      throw new FetchError(`Unknown error occurred during fetch to '${args[0]}'`, { cause: error })
    })

    if (response.ok && !isResponseContentType(expectedContentType, response)) {
      throw new InvalidFetchResponseError(
        `Expected response to match content type '${expectedContentType}', but received '${response.headers.get('Content-Type')}'`,
        await response.clone().text(),
        response
      )
    }

    if (expectedContentType === ContentType.OAuthAuthorizationRequestJwt) {
      return {
        response,
        result: response.ok ? schema.safeParse(await response.text()) : undefined,
      }
    }

    return {
      response,
      result: response.ok ? schema.safeParse(await response.json()) : undefined,
    }
  }
}
