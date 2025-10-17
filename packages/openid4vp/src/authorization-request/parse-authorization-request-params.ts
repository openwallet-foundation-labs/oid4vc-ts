import { decodeJwt } from '@openid4vc/oauth2'
import { parseWithErrorHandling } from '@openid4vc/utils'
import z from 'zod'
import {
  isJarAuthorizationRequest,
  type JarAuthorizationRequest,
  zJarAuthorizationRequest,
} from '../jar/z-jar-authorization-request'
import {
  type Openid4vpAuthorizationRequest,
  zOpenid4vpAuthorizationRequest,
  zOpenid4vpAuthorizationRequestFromUriParams,
} from './z-authorization-request'
import {
  isOpenid4vpAuthorizationRequestDcApi,
  type Openid4vpAuthorizationRequestDcApi,
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

export interface ParseOpenid4vpAuthorizationRequestOptions {
  authorizationRequest: string | Record<string, unknown>
}

export function parseOpenid4vpAuthorizationRequest(
  options: ParseOpenid4vpAuthorizationRequestOptions
): ParsedOpenid4vpAuthorizationRequest | ParsedJarRequest | ParsedOpenid4vpDcApiAuthorizationRequest {
  const { authorizationRequest } = options
  let provided: 'uri' | 'jwt' | 'params' = 'params'

  let params: Record<string, unknown>
  if (typeof authorizationRequest === 'string') {
    // JWT will never contain :
    if (authorizationRequest.includes(':')) {
      params = parseWithErrorHandling(
        zOpenid4vpAuthorizationRequestFromUriParams,
        authorizationRequest,
        'Unable to parse openid4vp authorization request uri to a valid object'
      )
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
