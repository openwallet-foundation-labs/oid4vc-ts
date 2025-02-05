import { Oauth2Error, decodeJwt } from '@openid4vc/oauth2'
import { uriDecodeObject } from '@openid4vc/utils'
import { type JarAuthRequest, zJarAuthRequest } from '../jar/z-jar-auth-request'
import { type Openid4vpAuthRequest, zOpenid4vpAuthRequest } from './z-openid4vp-auth-request'

export interface ParsedJarOpenid4vpAuthRequest {
  type: 'jar'
  provided: 'uri' | 'jwt' | 'params'
  params: JarAuthRequest
}

export interface ParsedOpenid4vpAuthRequest {
  type: 'openid4vp'
  provided: 'uri' | 'jwt' | 'params'
  params: Openid4vpAuthRequest
}

export function parseOpenid4vpRequestParams(
  input: unknown
): ParsedOpenid4vpAuthRequest | ParsedJarOpenid4vpAuthRequest {
  let params = input
  let provided: 'uri' | 'jwt' | 'params' = 'params'

  if (typeof input === 'string') {
    if (input.includes('://')) {
      const data = input.split('://')[1]
      params = uriDecodeObject(data)
      provided = 'uri'
    } else {
      const decoded = decodeJwt({ jwt: input })
      params = decoded.payload
      provided = 'jwt'
    }
  }

  const parsedOpenid4vpAuthRequest = zOpenid4vpAuthRequest.safeParse(params)
  if (parsedOpenid4vpAuthRequest.success) {
    return {
      type: 'openid4vp',
      provided,
      params: parsedOpenid4vpAuthRequest.data,
    }
  }

  const parsedJarAuthRequest = zJarAuthRequest.safeParse(params)
  if (parsedJarAuthRequest.success) {
    return {
      type: 'jar',
      provided,
      params: parsedJarAuthRequest.data,
    }
  }

  throw new Oauth2Error('Could not parse openid4vp auth request params.')
}
