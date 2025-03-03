import { type CallbackContext, Oauth2Error, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { parseOpenid4vpAuthorizationRequestPayload } from '../authorization-request/parse-authorization-request-params'
import type { Openid4vpAuthorizationRequest } from '../authorization-request/z-authorization-request'
import type { Openid4vpAuthorizationRequestDcApi } from '../authorization-request/z-authorization-request-dc-api'
import type {
  GetOpenid4vpAuthorizationRequestCallback,
  VerifiedJarmAuthorizationResponse,
} from '../jarm/jarm-auth-response/verify-jarm-auth-response'
import type { JarmHeader } from '../jarm/jarm-auth-response/z-jarm-auth-response'
import { isJarmResponseMode } from '../jarm/jarm-response-mode'
import { parseOpenid4VpAuthorizationResponsePayload } from './parse-authorization-response-payload'
import { parseJarmAuthorizationResponse } from './parse-jarm-authorization-response'
import { validateOpenid4vpAuthorizationResponsePayload } from './validate-authorization-response'
import type { ValidateOpenid4VpAuthorizationResponseResult } from './validate-authorization-response-result'
import type { Openid4vpAuthorizationResponse } from './z-authorization-response'

export interface ParseOpenid4vpAuthorizationResponseOptions {
  responsePayload: Record<string, unknown>
  callbacks: Pick<CallbackContext, 'decryptJwe' | 'verifyJwt'> & {
    getOpenid4vpAuthorizationRequest: GetOpenid4vpAuthorizationRequestCallback
  }
}

export type ParsedOpenid4vpAuthorizationResponse = ValidateOpenid4VpAuthorizationResponseResult & {
  authorizationResponsePayload: Openid4vpAuthorizationResponse
  authorizationRequestPayload: Openid4vpAuthorizationRequest | Openid4vpAuthorizationRequestDcApi

  expectedNonce: string

  // TODO: return this
  // expectedTransactionDataHashes?: []

  jarm?: VerifiedJarmAuthorizationResponse & {
    jarmHeader: JarmHeader
    mdocGeneratedNonce?: string
  }
}

export async function parseOpenid4vpAuthorizationResponse(
  options: ParseOpenid4vpAuthorizationResponseOptions
): Promise<ParsedOpenid4vpAuthorizationResponse> {
  const { responsePayload, callbacks } = options

  if (responsePayload.response) {
    return parseJarmAuthorizationResponse({ jarmResponseJwt: responsePayload.response as string, callbacks })
  }

  const authorizationResponsePayload = parseOpenid4VpAuthorizationResponsePayload(responsePayload)

  const { authorizationRequest } = await callbacks.getOpenid4vpAuthorizationRequest(authorizationResponsePayload)
  const parsedAuthRequest = parseOpenid4vpAuthorizationRequestPayload({ authorizationRequest: authorizationRequest })
  if (parsedAuthRequest.type !== 'openid4vp' && parsedAuthRequest.type !== 'openid4vp_dc_api') {
    throw new Oauth2Error('Invalid authorization request. Could not parse openid4vp authorization request.')
  }

  const authorizationRequestPayload = parsedAuthRequest.params

  const validateOpenId4vpResponse = validateOpenid4vpAuthorizationResponsePayload({
    requestPayload: authorizationRequestPayload,
    responsePayload: authorizationResponsePayload,
  })

  if (authorizationRequestPayload.response_mode && isJarmResponseMode(authorizationRequestPayload.response_mode)) {
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
    expectedNonce: authorizationRequestPayload.nonce,

    authorizationResponsePayload,
    authorizationRequestPayload,
    jarm: undefined,
  }
}
