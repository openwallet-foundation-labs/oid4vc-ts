import { type CallbackContext, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import type { Openid4vpAuthorizationRequest } from '../authorization-request/z-authorization-request'
import type { Openid4vpAuthorizationRequestDcApi } from '../authorization-request/z-authorization-request-dc-api'
import { getOpenid4vpClientId } from '../client-identifier-scheme/parse-client-identifier-scheme'
import type { VerifiedJarmAuthorizationResponse } from '../jarm/jarm-authorization-response/verify-jarm-authorization-response'
import type { JarmHeader } from '../jarm/jarm-authorization-response/z-jarm-authorization-response'
import { isJarmResponseMode } from '../jarm/jarm-response-mode'
import { parseOpenid4VpAuthorizationResponsePayload } from './parse-authorization-response-payload'
import { parseJarmAuthorizationResponse } from './parse-jarm-authorization-response'
import { validateOpenid4vpAuthorizationResponsePayload } from './validate-authorization-response'
import type { ValidateOpenid4VpAuthorizationResponseResult } from './validate-authorization-response-result'
import type { Openid4vpAuthorizationResponse } from './z-authorization-response'

export interface ParseOpenid4vpAuthorizationResponseOptions {
  /**
   * The authorization response as received from the wallet, and can optionally still be encrypted.
   */
  authorizationResponse: Record<string, unknown>

  authorizationRequestPayload: Openid4vpAuthorizationRequest | Openid4vpAuthorizationRequestDcApi
  callbacks: Pick<CallbackContext, 'decryptJwe' | 'verifyJwt'>

  origin?: string
}

export type ParsedOpenid4vpAuthorizationResponse = ValidateOpenid4VpAuthorizationResponseResult & {
  authorizationResponsePayload: Openid4vpAuthorizationResponse
  expectedNonce: string
  jarm?: VerifiedJarmAuthorizationResponse & {
    jarmHeader: JarmHeader
  }
}

export async function parseOpenid4vpAuthorizationResponse(
  options: ParseOpenid4vpAuthorizationResponseOptions
): Promise<ParsedOpenid4vpAuthorizationResponse> {
  const { authorizationResponse, callbacks, authorizationRequestPayload, origin } = options

  const expectedClientId = getOpenid4vpClientId({
    origin,
    authorizationRequestPayload,
  })
  if (authorizationResponse.response) {
    return parseJarmAuthorizationResponse({
      jarmResponseJwt: authorizationResponse.response as string,
      callbacks,
      authorizationRequestPayload,
      // If client_id_scheme was provided we should use the legacy (unprefixed) client id scheme
      // TODO: allow both versions, in case of e.g. did:
      expectedClientId: expectedClientId.legacyClientId ?? expectedClientId.clientId,
    })
  }

  const authorizationResponsePayload = parseOpenid4VpAuthorizationResponsePayload(authorizationResponse)

  const validatedOpenId4vpResponse = validateOpenid4vpAuthorizationResponsePayload({
    authorizationRequestPayload: authorizationRequestPayload,
    authorizationResponsePayload: authorizationResponsePayload,
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
    ...validatedOpenId4vpResponse,
    expectedNonce: authorizationRequestPayload.nonce,

    authorizationResponsePayload,
    jarm: undefined,
  }
}
