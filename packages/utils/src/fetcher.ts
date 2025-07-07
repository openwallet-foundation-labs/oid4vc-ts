import type z from 'zod'
import { ContentType, isResponseContentType } from './content-type'
import { FetchError } from './error/FetchError'
import { InvalidFetchResponseError } from './error/InvalidFetchResponseError'
import { type Fetch, URLSearchParams } from './globals'

/**
 * A type utility which represents the function returned
 * from createZodFetcher
 */
export type ZodFetcher = <Schema extends z.ZodTypeAny>(
  schema: Schema,
  expectedContentType: ContentType | ContentType[],
  ...args: Parameters<Fetch>
) => Promise<{ response: Awaited<ReturnType<Fetch>>; result?: z.SafeParseReturnType<Schema, z.infer<Schema>> }>

/**
 * The default fetcher used by createZodFetcher when no
 * fetcher is provided.
 */
// biome-ignore lint/style/noRestrictedGlobals: this is the only place where we use the global
const defaultFetcher = fetch

export function createFetcher(fetcher = defaultFetcher): Fetch {
  return (input, init, ...args) => {
    return fetcher(
      input,
      init
        ? {
            ...init,
            // React Native does not seem to handle the toString(). This is hard to catch when running
            // tests in Node.JS where this does work correctly. so we handle it here.
            body: init.body instanceof URLSearchParams ? init.body.toString() : init.body,
          }
        : undefined,
      ...args
    ).catch((error) => {
      throw new FetchError(`Unknown error occurred during fetch to '${input}'`, { cause: error })
    })
  }
}

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
export function createZodFetcher(fetcher?: Fetch): ZodFetcher {
  return async (schema, expectedContentType, ...args) => {
    const response = await createFetcher(fetcher)(...args)

    const expectedContentTypeArray = Array.isArray(expectedContentType) ? expectedContentType : [expectedContentType]

    if (response.ok && !isResponseContentType(expectedContentTypeArray, response)) {
      throw new InvalidFetchResponseError(
        `Expected response to match content type ${expectedContentTypeArray.join(' | ')}, but received '${response.headers.get('Content-Type')}'`,
        await response.clone().text(),
        response
      )
    }

    if (expectedContentTypeArray.includes(ContentType.OAuthAuthorizationRequestJwt)) {
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
