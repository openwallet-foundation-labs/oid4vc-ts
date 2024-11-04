import { parseWithErrorHandling } from '@animo-id/oauth2-utils'
import type { CallbackContext } from '../callbacks'
import { type AccessTokenResponse, vAccessTokenResponse } from './v-access-token'

export interface CreateAccessTokenResponseOptions {
  callbacks: Pick<CallbackContext, 'signJwt' | 'generateRandom' | 'hash'>

  /**
   * The access token
   */
  accessToken: string

  /**
   * The type of token. Should be DPoP if the access token
   * is bound to a dpop key
   */
  tokenType: 'DPoP' | 'Bearer' | (string & {})

  /**
   * Number of seconds after which the access tokens expires.
   */
  expiresInSeconds: number

  /**
   * New cNonce value
   */
  cNonce?: string
  cNonceExpiresIn?: number

  /**
   * Additional payload to include in the access token response.
   *
   * Will be applied after default payload to allow overriding over values, but be careful.
   */
  additionalPayload?: Record<string, unknown>
}

export async function createAccessTokenResponse(options: CreateAccessTokenResponseOptions) {
  const accessTokenResponse = parseWithErrorHandling(vAccessTokenResponse, {
    access_token: options.accessToken,
    token_type: options.tokenType,
    expires_in: options.expiresInSeconds,
    c_nonce: options.cNonce,
    c_nonce_expires_in: options.cNonceExpiresIn,
    ...options.additionalPayload,
  } satisfies AccessTokenResponse)

  return accessTokenResponse
}
