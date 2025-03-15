import type { FetchResponse } from './globals'

export enum ContentType {
  XWwwFormUrlencoded = 'application/x-www-form-urlencoded',
  Json = 'application/json',
  JwkSet = 'application/jwk-set+json',
  OAuthorizationRequestObjectJwt = 'application/oauth-authz-req+jwt',
  Jwt = 'application/jwt',
}

export function isContentType(contentType: ContentType, value: string) {
  return value.toLowerCase().trim().split(';')[0] === contentType
}

export function isResponseContentType(contentType: ContentType, response: FetchResponse) {
  const header = response.headers.get('Content-Type')
  if (!header) return false
  return isContentType(contentType, header)
}
