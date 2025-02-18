import { type CallbackContext, Oauth2Error, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { parseOpenid4vpAuthorizationRequestPayload } from '../authorization-request/parse-authorization-request-params'
import type { JarmAuthResponse, JarmAuthResponseEncryptedOnly } from '../jarm/jarm-auth-response/z-jarm-auth-response'
import { isJarmResponseMode } from '../jarm/jarm-response-mode'
import { parseOpenid4VpAuthorizationResponsePaylaod } from './parse-authorization-response-payload.js'
import { parseJarmAuthorizationResponse } from './parse-jarm-authorization-response.js'
import { validateOpenid4vpAuthorizationResponse } from './validate-authorization-response'
import { isOpenid4vpAuthorizationResponseDcApi } from './z-authorization-response-dc-api'

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
