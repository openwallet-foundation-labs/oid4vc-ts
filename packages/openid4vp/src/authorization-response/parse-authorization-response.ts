import {
  type CallbackContext,
  Oauth2Error,
  Oauth2ServerErrorResponseError,
  decodeJwtHeader,
  zCompactJwe,
  zCompactJwt,
  zJwtHeader,
} from '@openid4vc/oauth2'
import { decodeBase64, encodeToUtf8String, parseWithErrorHandling } from '@openid4vc/utils'
import z from 'zod'
import { parseOpenid4vpAuthorizationRequestPayload } from '../authorization-request/parse-authorization-request-params'
import { isOpenid4vpAuthorizationRequestDcApi } from '../authorization-request/z-authorization-request-dc-api'
import { verifyJarmAuthorizationResponse } from '../jarm/jarm-auth-response/verify-jarm-auth-response'
import type { JarmAuthResponse, JarmAuthResponseEncryptedOnly } from '../jarm/jarm-auth-response/z-jarm-auth-response'
import { isJarmResponseMode } from '../jarm/jarm-response-mode'
import { validateOpenid4vpAuthorizationResponse } from './validate-authorization-response'
import { zOpenid4vpAuthorizationResponse } from './z-authorization-response'
import {
  isOpenid4vpAuthorizationResponseDcApi,
  zOpenid4vpAuthorizationResponseDcApi,
} from './z-authorization-response-dc-api'

function parseOpenid4VpAuthorizationResponsePaylaod(payload: Record<string, unknown>) {
  if (isOpenid4vpAuthorizationRequestDcApi(payload)) {
    return parseWithErrorHandling(
      zOpenid4vpAuthorizationResponseDcApi,
      payload,
      'Invalid openid4vp authorization response.'
    )
  }

  return parseWithErrorHandling(zOpenid4vpAuthorizationResponse, payload, 'Invalid openid4vp authorization response.')
}

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

  const authResponsePayload = parseOpenid4VpAuthorizationResponsePaylaod(verifiedJarmResponse.jarmAuthResponse)
  const validateOpenId4vpResponse = validateOpenid4vpAuthorizationResponse({
    authorizationRequest: parsedAuthorizationRequest.params,
    authorizationResponse: isOpenid4vpAuthorizationResponseDcApi(authResponsePayload)
      ? authResponsePayload.data
      : authResponsePayload,
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

export interface ParseOpenid4vpAuthorizationResponseOptions {
  responsePayload: Record<string, unknown>
  callbacks: Pick<CallbackContext, 'decryptJwe' | 'verifyJwt'> & {
    getOpenid4vpAuthorizationRequest: (
      authResponse: JarmAuthResponse | JarmAuthResponseEncryptedOnly
    ) => Promise<{ authRequest: { client_id: string; nonce: string; state?: string } }>
  }
}

export async function parseOpenid4vpAuthorizationResponse(options: ParseOpenid4vpAuthorizationResponseOptions) {
  const { responsePayload, callbacks } = options

  if (responsePayload.response) {
    return parseJarmAuthorizationResponse({ jarmResponseJwt: responsePayload.response as string, callbacks })
  }

  const authResponsePayload = parseOpenid4VpAuthorizationResponsePaylaod(responsePayload)

  const authRequest = await callbacks.getOpenid4vpAuthorizationRequest(authResponsePayload)
  const parsedAuthRequest = parseOpenid4vpAuthorizationRequestPayload({ requestPayload: authRequest.authRequest })
  if (parsedAuthRequest.type !== 'openid4vp') {
    throw new Oauth2Error('Invalid authorization request. Could not parse openid4vp authorization request.')
  }

  const authRequestPayload = parsedAuthRequest.params

  const validateOpenId4vpResponse = validateOpenid4vpAuthorizationResponse({
    authorizationRequest: authRequestPayload,
    authorizationResponse: isOpenid4vpAuthorizationResponseDcApi(authResponsePayload)
      ? authResponsePayload.data
      : authResponsePayload,
  })

  if (authRequestPayload.response_mode && isJarmResponseMode(authRequestPayload.response_mode)) {
    throw new Oauth2ServerErrorResponseError(
      {
        error: 'invalid_request',
        error_description: 'Invalid response mode for openid4vp response. Expected jarm response.',
      },
      {
        status: 400,
      }
    )
  }

  return {
    ...validateOpenId4vpResponse,
    authResponsePayload,
    authRequestPayload,
    jarm: undefined,
  }
}

export type ParsedOpenid4vpAuthorizationResponse = Awaited<ReturnType<typeof parseOpenid4vpAuthorizationResponse>>
