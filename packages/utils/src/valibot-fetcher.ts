import * as v from 'valibot'
import { type ContentType, isResponseContentType } from './content-type'
import { InvalidFetchResponseError } from './error/InvalidFetchResponseError'
import type { Fetch } from './globals'

// biome-ignore lint/suspicious/noExplicitAny: any type needed for generic
export type ValibotFetcher = <Schema extends v.BaseSchema<any, any, any>>(
  schema: Schema,
  expectedContentType: ContentType,
  ...args: Parameters<Fetch>
) => Promise<{ response: Awaited<ReturnType<Fetch>>; result?: v.SafeParseResult<Schema> }>

/**
 * The default fetcher used when no
 * fetcher is provided.
 */
// @ts-ignore
// biome-ignore lint/style/noRestrictedGlobals: <explanation>
export const defaultFetcher = fetch

/**
 * Creates a `fetchWithValibot` function that takes in a schema of
 * the expected response, and the arguments to fetch.
 *
 * If you don't provide a fetcher in `createValibotFetcher()`,
 * we're falling back to the default fetcher.
 *
 * @example
 *
 * const fetchWithValibot = createValibotFetcher();
 *
 * const { response, data } = await fetchWithValibot(
 *   v.looseObject({
 *    format: v.string()
 *   }),
 *   "https://example.com",
 * );
 */
export function createValibotFetcher(
  /**
   * A fetcher function that returns a response, from which the data can be parsed
   */
  fetcher = defaultFetcher
): ValibotFetcher {
  return async (schema, expectedContentType, ...args) => {
    const response = await fetcher(...args)

    if (response.ok && !isResponseContentType(expectedContentType, response)) {
      throw new InvalidFetchResponseError(
        `Expected response to match content type '${expectedContentType}', but received '${response.headers.get('Content-Type')}'`,
        await response.clone().text(),
        response
      )
    }

    return {
      response,
      result: response.ok ? v.safeParse(schema, await response.json()) : undefined,
    }
  }
}
