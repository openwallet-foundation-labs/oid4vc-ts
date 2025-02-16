import { decodeJwt } from '@openid4vc/oauth2'
import { URL } from '@openid4vc/utils'
import { parseWithErrorHandling } from '@openid4vc/utils'
import z from 'zod'
import { type JarAuthRequest, isJarAuthRequest, zJarAuthRequest } from '../jar/z-jar-auth-request'
import { type Openid4vpAuthorizationRequest, zOpenid4vpAuthorizationRequest } from './z-authorization-request'
import {
  type Openid4vpAuthorizationRequestDcApi,
  isOpenid4vpAuthorizationRequestDcApi,
  zOpenid4vpAuthorizationRequestDcApi,
} from './z-authorization-request-dc-api'

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

export interface ParsedOpenid4vpDcApiAuthRequest {
  type: 'openid4vp_dc_api'
  provided: 'uri' | 'jwt' | 'params'
  params: Openid4vpAuthorizationRequestDcApi
}

export interface ParseOpenid4vpAuthRequestPayloadOptions {
  requestPayload: string | Record<string, unknown>
}

export function parseOpenid4vpAuthorizationRequestPayload(
  options: ParseOpenid4vpAuthRequestPayloadOptions
): ParsedOpenid4vpAuthRequest | ParsedJarOpenid4vpAuthRequest | ParsedOpenid4vpDcApiAuthRequest {
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

  const parsedRequest = parseWithErrorHandling(
    z.union([zOpenid4vpAuthorizationRequest, zJarAuthRequest, zOpenid4vpAuthorizationRequestDcApi]),
    params
  )

  if (isOpenid4vpAuthorizationRequestDcApi(parsedRequest)) {
    return {
      type: 'openid4vp_dc_api',
      provided,
      params: parsedRequest,
    }
  }

  if (isJarAuthRequest(parsedRequest)) {
    return {
      type: 'jar',
      provided,
      params: parsedRequest,
    }
  }

  return {
    type: 'openid4vp',
    provided,
    params: parsedRequest,
  }
}
