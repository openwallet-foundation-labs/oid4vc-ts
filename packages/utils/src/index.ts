export {
  type Fetch,
  Headers,
  type FetchRequestInit,
  type FetchHeaders,
  type FetchResponse,
  URL,
  URLSearchParams,
} from './globals'

export { JsonParseError } from './error/JsonParseError'
export { ValidationError } from './error/ValidationError'
export { InvalidFetchResponseError } from './error/InvalidFetchResponseError'

export { addSecondsToDate, dateToSeconds } from './date'
export { decodeBase64, decodeUtf8String, encodeToBase64, encodeToBase64Url, encodeToUtf8String } from './encoding'
export {
  parseWithErrorHandling,
  stringToJsonWithErrorHandling,
  type BaseSchema,
  type InferOutputUnion,
} from './parse'
export { joinUriParts } from './path'
export type { Optional, Simplify, StringWithAutoCompletion, OrPromise } from './type'
export { getQueryParams, objectToQueryParams } from './url'
export { type ZodFetcher, createZodFetcher, defaultFetcher } from './zod-fetcher'
export {
  type HttpMethod,
  zHttpMethod,
  zHttpsUrl,
  zInteger,
  zIs,
} from './validation'
export { mergeDeep } from './object'
export { arrayEqualsIgnoreOrder } from './array'
export {
  parseWwwAuthenticateHeader,
  type WwwAuthenticateHeaderChallenge,
  encodeWwwAuthenticateHeader,
} from './www-authenticate'
export { ContentType, isContentType, isResponseContentType } from './content-type'
export { setGlobalConfig, type Oid4vcTsConfig, getGlobalConfig } from './config'
