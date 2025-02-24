import {
  type CallbackContext,
  Oauth2Error,
  decodeJwtHeader,
  zCompactJwe,
  zCompactJwt,
  zJwtHeader,
} from '@openid4vc/oauth2'
import { decodeBase64, encodeToUtf8String, parseWithErrorHandling } from '@openid4vc/utils'
import z from 'zod'
import { parseOpenid4vpAuthorizationRequestPayload } from '../authorization-request/parse-authorization-request-params'
import { verifyJarmAuthorizationResponse } from '../jarm/jarm-auth-response/verify-jarm-auth-response'
import type { JarmAuthResponse, JarmAuthResponseEncryptedOnly } from '../jarm/jarm-auth-response/z-jarm-auth-response'
import { isJarmResponseMode } from '../jarm/jarm-response-mode'
import { parseOpenid4VpAuthorizationResponsePayload } from './parse-authorization-response-payload'
import { validateOpenid4vpAuthorizationResponse } from './validate-authorization-response'

export interface ParseJarmAuthorizationResponseOptions {
  jarmResponseJwt: string
  callbacks: Pick<CallbackContext, 'decryptJwe' | 'verifyJwt'> & {
    getOpenid4vpAuthorizationRequest: (
      authResponse: JarmAuthResponse | JarmAuthResponseEncryptedOnly
    ) => Promise<{ authRequest: { client_id: string; nonce: string; state?: string } }>
  }
}

export async function parseJarmAuthorizationResponse(options: ParseJarmAuthorizationResponseOptions) {
  const { jarmResponseJwt, callbacks } = options

  const jarmAuthorizationResponseJwt = parseWithErrorHandling(
    z.union([zCompactJwt, zCompactJwe]),
    jarmResponseJwt,
    'Invalid jarm authorization response jwt.'
  )

  const verifiedJarmResponse = await verifyJarmAuthorizationResponse({ jarmAuthorizationResponseJwt, callbacks })
  const zJarmHeader = z.object({ ...zJwtHeader.shape, apu: z.string().optional(), apv: z.string().optional() })
  const { header: jarmHeader } = decodeJwtHeader({
    jwt: jarmAuthorizationResponseJwt,
    headerSchema: zJarmHeader,
  })

  const parsedAuthorizationRequest = parseOpenid4vpAuthorizationRequestPayload({
    requestPayload: verifiedJarmResponse.authRequest,
  })

  if (parsedAuthorizationRequest.type !== 'openid4vp') {
    throw new Oauth2Error('Invalid authorization request. Could not parse openid4vp authorization request.')
  }

  const authResponsePayload = parseOpenid4VpAuthorizationResponsePayload(verifiedJarmResponse.jarmAuthResponse)
  const validateOpenId4vpResponse = validateOpenid4vpAuthorizationResponse({
    authorizationRequest: parsedAuthorizationRequest.params,
    authorizationResponse: authResponsePayload,
  })

  const authRequestPayload = parsedAuthorizationRequest.params
  if (!authRequestPayload.response_mode || !isJarmResponseMode(authRequestPayload.response_mode)) {
    throw new Oauth2Error(
      `Invalid response mode for jarm response. Response mode: '${authRequestPayload.response_mode ?? 'fragment'}'`
    )
  }

  let mdocGeneratedNonce: string | undefined = undefined

  if (jarmHeader?.apu) {
    mdocGeneratedNonce = encodeToUtf8String(decodeBase64(jarmHeader.apu))
  }
  if (jarmHeader?.apv) {
    const jarmRequestNonce = encodeToUtf8String(decodeBase64(jarmHeader.apv))
    if (jarmRequestNonce !== authRequestPayload.nonce) {
      throw new Oauth2Error('The nonce in the jarm header does not match the nonce in the request.')
    }
  }

  return {
    ...validateOpenId4vpResponse,
    jarm: { ...verifiedJarmResponse, jarmHeader, mdocGeneratedNonce },
    authResponsePayload,
    authRequestPayload,
  }
}
