import { type CallbackContext, Oauth2Error, decodeJwtHeader, zCompactJwe, zCompactJwt } from '@openid4vc/oauth2'
import { decodeBase64, encodeToUtf8String, parseWithErrorHandling } from '@openid4vc/utils'
import z from 'zod'
import { parseOpenid4vpAuthorizationRequestPayload } from '../authorization-request/parse-authorization-request-params'
import {
  type GetOpenid4vpAuthorizationRequestCallback,
  verifyJarmAuthorizationResponse,
} from '../jarm/jarm-auth-response/verify-jarm-auth-response'
import { isJarmResponseMode } from '../jarm/jarm-response-mode'
import { parseOpenid4VpAuthorizationResponsePayload } from './parse-authorization-response-payload'
import { validateOpenid4vpAuthorizationResponsePayload } from './validate-authorization-response'
import { zJarmHeader } from '../jarm/jarm-auth-response/z-jarm-auth-response'
import type { ParsedOpenid4vpAuthorizationResponse } from './parse-authorization-response'

export interface ParseJarmAuthorizationResponseOptions {
  jarmResponseJwt: string
  callbacks: Pick<CallbackContext, 'decryptJwe' | 'verifyJwt'> & {
    getOpenid4vpAuthorizationRequest: GetOpenid4vpAuthorizationRequestCallback
  }
}

export async function parseJarmAuthorizationResponse(
  options: ParseJarmAuthorizationResponseOptions
): Promise<ParsedOpenid4vpAuthorizationResponse> {
  const { jarmResponseJwt, callbacks } = options

  const jarmAuthorizationResponseJwt = parseWithErrorHandling(
    z.union([zCompactJwt, zCompactJwe]),
    jarmResponseJwt,
    'Invalid jarm authorization response jwt.'
  )

  const verifiedJarmResponse = await verifyJarmAuthorizationResponse({ jarmAuthorizationResponseJwt, callbacks })

  const { header: jarmHeader } = decodeJwtHeader({
    jwt: jarmAuthorizationResponseJwt,
    headerSchema: zJarmHeader,
  })

  const parsedAuthorizationRequest = parseOpenid4vpAuthorizationRequestPayload({
    authorizationRequest: verifiedJarmResponse.authorizationRequest,
  })

  if (parsedAuthorizationRequest.type !== 'openid4vp' && parsedAuthorizationRequest.type !== 'openid4vp_dc_api') {
    throw new Oauth2Error('Invalid authorization request. Could not parse openid4vp authorization request.')
  }

  const authorizationResponsePayload = parseOpenid4VpAuthorizationResponsePayload(verifiedJarmResponse.jarmAuthResponse)
  const validateOpenId4vpResponse = validateOpenid4vpAuthorizationResponsePayload({
    requestPayload: parsedAuthorizationRequest.params,
    responsePayload: authorizationResponsePayload,
  })

  const authorizationRequestPayload = parsedAuthorizationRequest.params
  if (!authorizationRequestPayload.response_mode || !isJarmResponseMode(authorizationRequestPayload.response_mode)) {
    throw new Oauth2Error(
      `Invalid response mode for jarm response. Response mode: '${authorizationRequestPayload.response_mode ?? 'fragment'}'`
    )
  }

  let mdocGeneratedNonce: string | undefined = undefined

  if (jarmHeader?.apu) {
    mdocGeneratedNonce = encodeToUtf8String(decodeBase64(jarmHeader.apu))
  }
  if (jarmHeader?.apv) {
    const jarmRequestNonce = encodeToUtf8String(decodeBase64(jarmHeader.apv))
    if (jarmRequestNonce !== authorizationRequestPayload.nonce) {
      throw new Oauth2Error('The nonce in the jarm header does not match the nonce in the request.')
    }
  }

  return {
    ...validateOpenId4vpResponse,
    jarm: { ...verifiedJarmResponse, jarmHeader, mdocGeneratedNonce },

    expectedNonce: authorizationRequestPayload.nonce,
    authorizationResponsePayload,
    authorizationRequestPayload,
  }
}
