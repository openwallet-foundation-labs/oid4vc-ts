import { Oauth2Error, decodeJwt } from '@openid4vc/oauth2'
import { URL } from '@openid4vc/utils'
import { parseWithErrorHandling } from '@openid4vc/utils'
import z from 'zod'
import { type JarAuthRequest, zJarAuthRequest } from '../jar/z-jar-auth-request'
import { type Openid4vpAuthorizationRequest, zOpenid4vpAuthorizationRequest } from './z-authorization-request'

export interface ParsedJarOpenid4vpAuthRequest {
  type: 'jar'
  provided: 'uri' | 'jwt' | 'params'
  params: JarAuthRequest
}

export interface ParsedOpenid4vpAuthRequest {
  type: 'openid4vp'
  provided: 'uri' | 'jwt' | 'params'
  params: Openid4vpAuthorizationRequest
}

export interface ParseOpenid4vpAuthRequestPayloadOptions {
  requestPayload: string | Record<string, unknown>
}

export function parseOpenid4vpAuthorizationRequestPayload(
  options: ParseOpenid4vpAuthRequestPayloadOptions
): ParsedOpenid4vpAuthRequest | ParsedJarOpenid4vpAuthRequest {
  const { requestPayload } = options
  let provided: 'uri' | 'jwt' | 'params' = 'params'

  let params: Record<string, unknown>
  if (typeof requestPayload === 'string') {
    if (requestPayload.includes('://')) {
      const url = new URL(requestPayload)
      params = Object.fromEntries(url.searchParams)
      provided = 'uri'
    } else {
      const decoded = decodeJwt({ jwt: requestPayload })
      params = decoded.payload
      provided = 'jwt'
    }
  } else {
    params = requestPayload
  }

  const parsedRequest = parseWithErrorHandling(z.union([zOpenid4vpAuthorizationRequest, zJarAuthRequest]), params)
  const parsedOpenid4vpAuthRequest = zOpenid4vpAuthorizationRequest.safeParse(parsedRequest)
  if (parsedOpenid4vpAuthRequest.success) {
    return {
      type: 'openid4vp',
      provided,
      params: parsedOpenid4vpAuthRequest.data,
    }
  }

  const parsedJarAuthRequest = zJarAuthRequest.safeParse(parsedRequest)
  if (parsedJarAuthRequest.success) {
    return {
      type: 'jar',
      provided,
      params: parsedJarAuthRequest.data,
    }
  }

  throw new Oauth2Error(
    'Could not parse openid4vp auth request params. The received is neither a valid openid4vp auth request nor a valid jar auth request.'
  )
}
