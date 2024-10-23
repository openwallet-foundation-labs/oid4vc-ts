import * as v from 'valibot'

// @ts-ignore
export type Fetch = typeof fetch
export type FetchResponse = Awaited<ReturnType<Fetch>>
export type FetchHeaders = FetchResponse['headers']

// biome-ignore lint/suspicious/noExplicitAny: any type needed for generic
export type ValibotFetcher = <Schema extends v.BaseSchema<any, any, any>>(
  schema: Schema,
  ...args: Parameters<Fetch>
) => Promise<{ response: Awaited<ReturnType<Fetch>>; result?: v.SafeParseResult<Schema> }>

/**
 * The default fetcher used when no
 * fetcher is provided.
 */
// @ts-ignore
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
  return async (schema, ...args) => {
    const response = await fetcher(...args)

    return {
      response,
      result: response.ok ? v.safeParse(schema, await response.json()) : undefined,
    }
  }
}
