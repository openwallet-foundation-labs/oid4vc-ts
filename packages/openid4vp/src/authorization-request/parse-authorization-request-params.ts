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

export interface ParsedJarRequest {
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
  authorizationRequest: string | Record<string, unknown>
}

export function parseOpenid4vpAuthorizationRequestPayload(
  options: ParseOpenid4vpAuthRequestPayloadOptions
): ParsedOpenid4vpAuthRequest | ParsedJarRequest | ParsedOpenid4vpDcApiAuthRequest {
  const { authorizationRequest } = options
  let provided: 'uri' | 'jwt' | 'params' = 'params'

  let params: Record<string, unknown>
  if (typeof authorizationRequest === 'string') {
    if (authorizationRequest.includes('://')) {
      const url = new URL(authorizationRequest)
      params = Object.fromEntries(url.searchParams)
      provided = 'uri'
    } else {
      const decoded = decodeJwt({ jwt: authorizationRequest })
      params = decoded.payload
      provided = 'jwt'
    }
  } else {
    params = authorizationRequest
  }

  const parsedRequest = parseWithErrorHandling(
    z.union([zOpenid4vpAuthorizationRequest, zJarAuthRequest, zOpenid4vpAuthorizationRequestDcApi]),
    params
  )

  if (isJarAuthRequest(parsedRequest)) {
    return {
      type: 'jar',
      provided,
      params: parsedRequest,
    }
  }

  if (isOpenid4vpAuthorizationRequestDcApi(parsedRequest)) {
    return {
      type: 'openid4vp_dc_api',
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
