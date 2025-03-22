export {
  Headers,
  URL,
  URLSearchParams,
  type Fetch,
  type FetchHeaders,
  type FetchRequestInit,
  type FetchResponse,
} from './globals'

export { InvalidFetchResponseError } from './error/InvalidFetchResponseError'
export { JsonParseError } from './error/JsonParseError'
export { ValidationError } from './error/ValidationError'

export { arrayEqualsIgnoreOrder } from './array'
export { getGlobalConfig, setGlobalConfig, type Oid4vcTsConfig } from './config'
export { ContentType, isContentType, isResponseContentType } from './content-type'
export { addSecondsToDate, dateToSeconds } from './date'
export {
  decodeBase64,
  decodeUtf8String,
  encodeToBase64,
  encodeToBase64Url,
  encodeToUtf8String,
} from './encoding'
export { mergeDeep } from './object'
export {
  parseWithErrorHandling,
  stringToJsonWithErrorHandling,
  parseIfJson,
  type BaseSchema,
  type InferOutputUnion,
} from './parse'
export { joinUriParts } from './path'
export type { Optional, OrPromise, Simplify, StringWithAutoCompletion } from './type'
export { getQueryParams, objectToQueryParams } from './url'
export { type ZodFetcher, createZodFetcher, createFetcher } from './fetcher'
export {
  type HttpMethod,
  zHttpMethod,
  zHttpsUrl,
  zInteger,
  zIs,
  zStringToJson,
} from './validation'
export {
  encodeWwwAuthenticateHeader,
  parseWwwAuthenticateHeader,
  type WwwAuthenticateHeaderChallenge,
} from './www-authenticate'

export { isObject } from './object'
