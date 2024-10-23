import * as v from 'valibot'
import { ContentType } from '../../common/content-type'
import {
  authorizationCodeGrantIdentifier,
  preAuthorizedCodeGrantIdentifier,
} from '../../credential-offer/v-credential-offer'
import { Oid4vcInvalidFetchResponseError } from '../../error/Oid4vcInvalidFetchResponseError'
import { Oid4vcOauthErrorResponseError } from '../../error/Oid4vcOauthErrorResponseError'
import { Oid4vcValidationError } from '../../error/Oid4vcValidationError'
import type { IssuerMetadataResult } from '../../metadata/fetch-issuer-metadata'
import { objectToQueryParams } from '../../utils/url'
import {
  type AccessTokenRequest,
  type AccessTokenResponse,
  vAccessTokenErrorResponse,
  vAccessTokenRequest,
  vAccessTokenRequestDraft14To11,
  vAccessTokenResponse,
} from './v-access-token'
import { parseWithErrorHandling } from '../../common/validation/parse'
import { Oid4vciDraftVersion } from '../../versions/draft-version'
import {
  createDpopJwt,
  type ResponseDpopReturn,
  type RequestDpopOptions,
  extractDpopNonceFromHeaders,
} from '../dpop/dpop'
import { shouldRetryTokenRequestWithDPoPNonce } from '../dpop/dpop-retry'
import type { CallbackContext } from '../../callbacks'
import { getAuthorizationServerMetadataFromList } from '../../metadata/authorization-server/authorization-server-metadata'
import { createValibotFetcher } from '../../utils/valibot-fetcher'

export interface RetrieveAccessTokenReturn {
  accessTokenResponse: AccessTokenResponse
  dpop?: ResponseDpopReturn
}

interface RetrieveAccessTokenBaseOptions {
  /**
   * The issuer identifier of the authorization server to use.
   */
  authorizationServer: string

  /**
   * Metadata of the credential issuer and authorization servers.
   */
  issuerMetadata: IssuerMetadataResult

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
    authorizationServer: options.authorizationServer,
    issuerMetadata: options.issuerMetadata,
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
    authorizationServer: options.authorizationServer,
    issuerMetadata: options.issuerMetadata,
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

async function retrieveAccessTokenWithDpopRetry(options: RetrieveAccessTokenOptions) {
  try {
    return await retrieveAccessToken(options)
  } catch (error) {
    if (options.dpop && error instanceof Oid4vcOauthErrorResponseError) {
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

/**
 * Internal method
 */
async function retrieveAccessToken(options: RetrieveAccessTokenOptions): Promise<RetrieveAccessTokenReturn> {
  const fetchWithValibot = createValibotFetcher(options.callbacks.fetch)

  const authorizationServerMetadata = getAuthorizationServerMetadataFromList(
    options.issuerMetadata.authorizationServers,
    options.authorizationServer
  )

  const dpopJwt = options.dpop
    ? await createDpopJwt({
        httpMethod: 'POST',
        requestUri: authorizationServerMetadata.token_endpoint,
        signer: options.dpop.signer,
        callbacks: options.callbacks,
        nonce: options.dpop.nonce,
      })
    : undefined

  let accessTokenRequest = parseWithErrorHandling(
    vAccessTokenRequest,
    options.request,
    'Error validating access token request'
  )
  if (options.issuerMetadata.originalDraftVersion === Oid4vciDraftVersion.Draft11) {
    accessTokenRequest = parseWithErrorHandling(
      vAccessTokenRequestDraft14To11,
      accessTokenRequest,
      'Error transforming draft 14 access token request into draft 11 request'
    )
  }

  const requestQueryParams = objectToQueryParams(accessTokenRequest)

  const { response, result } = await fetchWithValibot(
    vAccessTokenResponse,
    authorizationServerMetadata.token_endpoint,
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
      throw new Oid4vcOauthErrorResponseError(
        `Unable to retrieve access token from '${authorizationServerMetadata.token_endpoint}'. Received token error response with status ${response.status}`,
        tokenErrorResponse.output,
        response
      )
    }

    throw new Oid4vcInvalidFetchResponseError(
      `Unable to retrieve access token from '${authorizationServerMetadata.token_endpoint}'. Received response with status ${response.status}`,
      await response.clone().text(),
      response
    )
  }

  if (!result.success) {
    throw new Oid4vcValidationError('Error validating access token response', result.issues)
  }

  const dpopNonce = extractDpopNonceFromHeaders(response.headers)
  return {
    dpop: dpopNonce
      ? {
          nonce: dpopNonce,
        }
      : undefined,
    accessTokenResponse: result.output,
  }
}
