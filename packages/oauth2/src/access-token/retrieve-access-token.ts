import { ContentType, createValibotFetcher, objectToQueryParams, parseWithErrorHandling } from '@animo-id/oauth2-utils'
import * as v from 'valibot'
import { ValidationError } from '../../../utils/src/error/ValidationError'
import type { CallbackContext } from '../callbacks'
import { type RequestDpopOptions, createDpopJwt, extractDpopNonceFromHeaders } from '../dpop/dpop'
import { shouldRetryTokenRequestWithDPoPNonce } from '../dpop/dpop-retry'
import { Oauth2ClientErrorResponseError } from '../error/Oauth2ClientErrorResponseError'
import { Oauth2InvalidFetchResponseError } from '../error/Oauth2InvalidFetchResponseError'
import type { AuthorizationServerMetadata } from '../metadata/authorization-server/v-authorization-server-metadata'
import { authorizationCodeGrantIdentifier, preAuthorizedCodeGrantIdentifier } from '../v-grant-type'
import {
  type AccessTokenRequest,
  type AccessTokenResponse,
  vAccessTokenErrorResponse,
  vAccessTokenRequest,
  vAccessTokenResponse,
} from './v-access-token'

export interface RetrieveAccessTokenReturn {
  accessTokenResponse: AccessTokenResponse
  dpop?: RequestDpopOptions
}

interface RetrieveAccessTokenBaseOptions {
  /**
   * Authorization server to request the access token from
   */
  authorizationServerMetadata: AuthorizationServerMetadata

  /**
   * Callbacks to use for requesting access token
   */
  callbacks: Pick<CallbackContext, 'fetch' | 'generateRandom' | 'hash' | 'signJwt'>

  /**
   * Dpop parameters for including a dpop in the access token request. The request will automatically
   * be retried if the server responds with a 'use_dpop_nonce' header.
   *
   * If provided but 'dpop_signing_alg_values_supported' is not available in the authorization server
   * metadata, or the 'alg' value does not match an error will be thrown.
   */
  dpop?: RequestDpopOptions
}

export interface RetrievePreAuthorizedCodeAccessTokenOptions extends RetrieveAccessTokenBaseOptions {
  preAuthorizedCode: string
  txCode?: string

  /**
   * Additional payload to include in the access token request. Items will be encoded and sent
   * using x-www-form-urlencoded format. Nested items (JSON) will be stringified and url encoded.
   */
  additionalRequestPayload?: Record<string, unknown>
}

export async function retrievePreAuthorizedCodeAccessToken(
  options: RetrievePreAuthorizedCodeAccessTokenOptions
): Promise<RetrieveAccessTokenReturn> {
  const request = {
    grant_type: preAuthorizedCodeGrantIdentifier,
    'pre-authorized_code': options.preAuthorizedCode,
    tx_code: options.txCode,
    ...options.additionalRequestPayload,
  } satisfies AccessTokenRequest

  const accessTokenResponse = await retrieveAccessTokenWithDpopRetry({
    authorizationServerMetadata: options.authorizationServerMetadata,
    request,
    dpop: options.dpop,
    callbacks: options.callbacks,
  })

  return accessTokenResponse
}

export interface RetrieveAuthorizationCodeAccessTokenOptions extends RetrieveAccessTokenBaseOptions {
  /**
   * PKCE Code verifier that was used in the authorization request.
   */
  pkceCodeVerifier?: string

  /**
   * The authorization code
   */
  authorizationCode: string

  /**
   * Redirect uri to include in the access token request. Only required
   * if the redirect uri was present in the authorization request.
   */
  redirectUri?: string

  /**
   * Additional payload to include in the access token request. Items will be encoded and sent
   * using x-www-form-urlencoded format. Nested items (JSON) will be stringified and url encoded.
   */
  additionalRequestPayload?: Record<string, unknown>
}

export async function retrieveAuthorizationCodeAccessToken(
  options: RetrieveAuthorizationCodeAccessTokenOptions
): Promise<RetrieveAccessTokenReturn> {
  const request = {
    grant_type: authorizationCodeGrantIdentifier,
    code: options.authorizationCode,
    code_verifier: options.pkceCodeVerifier,
    redirect_uri: options.redirectUri,
    ...options.additionalRequestPayload,
  } satisfies AccessTokenRequest

  const accessTokenResponse = await retrieveAccessTokenWithDpopRetry({
    authorizationServerMetadata: options.authorizationServerMetadata,
    request,
    dpop: options.dpop,
    callbacks: options.callbacks,
  })

  return accessTokenResponse
}

interface RetrieveAccessTokenOptions extends RetrieveAccessTokenBaseOptions {
  /**
   * The access token request body
   */
  request: AccessTokenRequest
}

/**
 * Internal method
 */
async function retrieveAccessToken(options: RetrieveAccessTokenOptions): Promise<RetrieveAccessTokenReturn> {
  const fetchWithValibot = createValibotFetcher(options.callbacks.fetch)

  const dpopJwt = options.dpop
    ? await createDpopJwt({
        request: {
          method: 'POST',
          url: options.authorizationServerMetadata.token_endpoint,
        },
        signer: options.dpop.signer,
        callbacks: options.callbacks,
        nonce: options.dpop.nonce,
      })
    : undefined

  const accessTokenRequest = parseWithErrorHandling(
    vAccessTokenRequest,
    options.request,
    'Error validating access token request'
  )

  // For backwards compat with draft 11 (we send both)
  if (accessTokenRequest.tx_code) {
    accessTokenRequest.user_pin = accessTokenRequest.tx_code
  }

  const requestQueryParams = objectToQueryParams(accessTokenRequest)
  const { response, result } = await fetchWithValibot(
    vAccessTokenResponse,
    options.authorizationServerMetadata.token_endpoint,
    {
      body: requestQueryParams,
      method: 'POST',
      headers: {
        'Content-Type': ContentType.XWwwFormUrlencoded,
        ...(dpopJwt ? { DPoP: dpopJwt } : {}),
      },
    }
  )

  if (!response.ok || !result) {
    const tokenErrorResponse = v.safeParse(
      vAccessTokenErrorResponse,
      await response
        .clone()
        .json()
        .catch(() => null)
    )
    if (tokenErrorResponse.success) {
      throw new Oauth2ClientErrorResponseError(
        `Unable to retrieve access token from '${options.authorizationServerMetadata.token_endpoint}'. Received token error response with status ${response.status}`,
        tokenErrorResponse.output,
        response
      )
    }

    throw new Oauth2InvalidFetchResponseError(
      `Unable to retrieve access token from '${options.authorizationServerMetadata.token_endpoint}'. Received response with status ${response.status}`,
      await response.clone().text(),
      response
    )
  }

  if (!result.success) {
    throw new ValidationError('Error validating access token response', result.issues)
  }

  const dpopNonce = extractDpopNonceFromHeaders(response.headers) ?? undefined
  return {
    dpop: options.dpop
      ? {
          nonce: dpopNonce,
          signer: options.dpop.signer,
        }
      : undefined,
    accessTokenResponse: result.output,
  }
}

async function retrieveAccessTokenWithDpopRetry(options: RetrieveAccessTokenOptions) {
  try {
    return await retrieveAccessToken(options)
  } catch (error) {
    if (options.dpop && error instanceof Oauth2ClientErrorResponseError) {
      const dpopRetry = shouldRetryTokenRequestWithDPoPNonce({
        responseHeaders: error.response.headers,
        tokenErrorResponse: error.errorResponse,
      })

      // Retry with the dpop nonce
      if (dpopRetry.retry) {
        return retrieveAccessToken({
          ...options,
          dpop: {
            ...options.dpop,
            nonce: dpopRetry.dpopNonce,
          },
        })
      }
    }

    throw error
  }
}
