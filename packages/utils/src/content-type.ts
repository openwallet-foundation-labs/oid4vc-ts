import type { FetchResponse } from './globals'

export enum ContentType {
  XWwwFormUrlencoded = 'application/x-www-form-urlencoded',
  Json = 'application/json',
}

export function isContentType(contentType: ContentType, value: string) {
  return value.toLowerCase().trim().split(';')[0] === contentType
}

export function isResponseContentType(contentType: ContentType, response: FetchResponse) {
  const header = response.headers.get('Content-Type')
  if (!header) return false
  return isContentType(contentType, header)
}
