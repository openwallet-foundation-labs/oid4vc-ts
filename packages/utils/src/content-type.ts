import type { FetchResponse } from './globals'

export enum ContentType {
  XWwwFormUrlencoded = 'application/x-www-form-urlencoded',
  Json = 'application/json',
  JwkSet = 'application/jwk-set+json',
  OAuthAuthorizationRequestJwt = 'application/oauth-authz-req+jwt',
  Jwt = 'application/jwt',
  Html = 'text/html',
}

export function isContentType(contentType: ContentType, value: string) {
  return value.toLowerCase().includes(contentType)
}

export function isResponseContentType(contentType: ContentType | ContentType[], response: FetchResponse) {
  const contentTypeArray = Array.isArray(contentType) ? contentType : [contentType]

  const header = response.headers.get('Content-Type')
  if (!header) return false
  return contentTypeArray.some((contentTypeEntry) => isContentType(contentTypeEntry, header))
}
