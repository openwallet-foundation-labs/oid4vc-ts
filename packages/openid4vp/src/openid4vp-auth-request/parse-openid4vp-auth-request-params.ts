import { Oauth2Error, decodeJwt } from '@openid4vc/oauth2'
import { uriDecodeObject } from '@openid4vc/utils'
import * as v from 'valibot'
import { type JarAuthRequest, vJarAuthRequest } from '../jar/v-jar-auth-request'
import { type Openid4vpAuthRequest, vOpenid4vpAuthRequest } from './v-openid4vp-auth-request'

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

  if (v.is(vOpenid4vpAuthRequest, params)) {
    return {
      type: 'openid4vp',
      provided,
      params: v.parse(vOpenid4vpAuthRequest, params),
    }
  }

  if (v.is(vJarAuthRequest, params)) {
    return {
      type: 'jar',
      provided,
      params,
    }
  }

  throw new Oauth2Error('Could not parse openid4vp auth request params.')
}
