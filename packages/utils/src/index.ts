export { arrayEqualsIgnoreOrder } from './array'
export { getGlobalConfig, type Oid4vcTsConfig, setGlobalConfig } from './config'
export { ContentType, isContentType, isResponseContentType } from './content-type'
export { addSecondsToDate, dateToSeconds } from './date'
export {
  decodeBase64,
  decodeUtf8String,
  encodeToBase64,
  encodeToBase64Url,
  encodeToUtf8String,
} from './encoding'
export { InvalidFetchResponseError } from './error/InvalidFetchResponseError'
export { JsonParseError } from './error/JsonParseError'
export { ValidationError } from './error/ValidationError'
export { createFetcher, createZodFetcher, type ZodFetcher } from './fetcher'
export {
  type Fetch,
  type FetchHeaders,
  type FetchRequestInit,
  type FetchResponse,
  Headers,
  URL,
  URLSearchParams,
} from './globals'
export { isObject, mergeDeep } from './object'
export {
  type BaseSchema,
  type InferOutputUnion,
  parseIfJson,
  parseWithErrorHandling,
  stringToJsonWithErrorHandling,
} from './parse'
export { joinUriParts } from './path'
export type { NonEmptyArray, Optional, OrPromise, Simplify, StringWithAutoCompletion } from './type'
export { getQueryParams, objectToQueryParams } from './url'
export {
  type HttpMethod,
  zDataUrl,
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
export { formatZodError } from './zod-error'
