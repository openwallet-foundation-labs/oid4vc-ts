import { decodeJwt } from '@openid4vc/oauth2'
import { URL } from '@openid4vc/utils'
import { parseWithErrorHandling } from '@openid4vc/utils'
import z from 'zod'
import {
  type JarAuthorizationRequest,
  isJarAuthorizationRequest,
  zJarAuthorizationRequest,
} from '../jar/z-jar-authorization-request'
import { type Openid4vpAuthorizationRequest, zOpenid4vpAuthorizationRequest } from './z-authorization-request'
import {
  type Openid4vpAuthorizationRequestDcApi,
  isOpenid4vpAuthorizationRequestDcApi,
  zOpenid4vpAuthorizationRequestDcApi,
} from './z-authorization-request-dc-api'

export interface ParsedJarRequest {
  type: 'jar'
  provided: 'uri' | 'jwt' | 'params'
  params: JarAuthorizationRequest
}

export interface ParsedOpenid4vpAuthorizationRequest {
  type: 'openid4vp'
  provided: 'uri' | 'jwt' | 'params'
  params: Openid4vpAuthorizationRequest
}

export interface ParsedOpenid4vpDcApiAuthorizationRequest {
  type: 'openid4vp_dc_api'
  provided: 'uri' | 'jwt' | 'params'
  params: Openid4vpAuthorizationRequestDcApi
}

export interface ParseOpenid4vpAuthorizationRequestPayloadOptions {
  authorizationRequest: string | Record<string, unknown>
}

export function parseOpenid4vpAuthorizationRequestPayload(
  options: ParseOpenid4vpAuthorizationRequestPayloadOptions
): ParsedOpenid4vpAuthorizationRequest | ParsedJarRequest | ParsedOpenid4vpDcApiAuthorizationRequest {
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
    z.union([zOpenid4vpAuthorizationRequest, zJarAuthorizationRequest, zOpenid4vpAuthorizationRequestDcApi]),
    params
  )

  if (isJarAuthorizationRequest(parsedRequest)) {
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
