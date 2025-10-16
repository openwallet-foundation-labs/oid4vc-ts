import { type CallbackContext, decodeJwtHeader, Oauth2Error, zCompactJwe, zCompactJwt } from '@openid4vc/oauth2'
import { parseWithErrorHandling } from '@openid4vc/utils'
import z from 'zod'
import type { Openid4vpAuthorizationRequest } from '../authorization-request/z-authorization-request'
import type { Openid4vpAuthorizationRequestDcApi } from '../authorization-request/z-authorization-request-dc-api'
import { verifyJarmAuthorizationResponse } from '../jarm/jarm-authorization-response/verify-jarm-authorization-response'
import { zJarmHeader } from '../jarm/jarm-authorization-response/z-jarm-authorization-response'
import { isJarmResponseMode } from '../jarm/jarm-response-mode'
import type { ParsedOpenid4vpAuthorizationResponse } from './parse-authorization-response'
import { parseOpenid4VpAuthorizationResponsePayload } from './parse-authorization-response-payload'
import { validateOpenid4vpAuthorizationResponsePayload } from './validate-authorization-response'

export interface ParseJarmAuthorizationResponseOptions {
  jarmResponseJwt: string
  authorizationRequestPayload: Openid4vpAuthorizationRequest | Openid4vpAuthorizationRequestDcApi
  callbacks: Pick<CallbackContext, 'decryptJwe' | 'verifyJwt'>

  expectedClientId: string
}

export async function parseJarmAuthorizationResponse(
  options: ParseJarmAuthorizationResponseOptions
): Promise<ParsedOpenid4vpAuthorizationResponse> {
  const { jarmResponseJwt, callbacks, authorizationRequestPayload, expectedClientId } = options

  const jarmAuthorizationResponseJwt = parseWithErrorHandling(
    z.union([zCompactJwt, zCompactJwe]),
    jarmResponseJwt,
    'Invalid jarm authorization response jwt.'
  )

  const verifiedJarmResponse = await verifyJarmAuthorizationResponse({
    jarmAuthorizationResponseJwt,
    callbacks,
    expectedClientId,
    authorizationRequestPayload,
  })

  const { header: jarmHeader } = decodeJwtHeader({
    jwt: jarmAuthorizationResponseJwt,
    headerSchema: zJarmHeader,
  })

  const authorizationResponsePayload = parseOpenid4VpAuthorizationResponsePayload(
    verifiedJarmResponse.jarmAuthorizationResponse
  )
  const validateOpenId4vpResponse = validateOpenid4vpAuthorizationResponsePayload({
    authorizationRequestPayload: authorizationRequestPayload,
    authorizationResponsePayload: authorizationResponsePayload,
  })

  if (!authorizationRequestPayload.response_mode || !isJarmResponseMode(authorizationRequestPayload.response_mode)) {
    throw new Oauth2Error(
      `Invalid response mode for jarm response. Response mode: '${authorizationRequestPayload.response_mode ?? 'fragment'}'`
    )
  }

  return {
    ...validateOpenId4vpResponse,
    jarm: { ...verifiedJarmResponse, jarmHeader },

    expectedNonce: authorizationRequestPayload.nonce,
    authorizationResponsePayload,
  }
}
