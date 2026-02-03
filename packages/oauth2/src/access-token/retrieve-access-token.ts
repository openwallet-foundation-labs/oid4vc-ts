import {
  ContentType,
  createZodFetcher,
  Headers,
  InvalidFetchResponseError,
  objectToQueryParams,
  parseWithErrorHandling,
} from '@openid4vc/utils'
import { ValidationError } from '../../../utils/src/error/ValidationError'
import type { CallbackContext } from '../callbacks'
import { createDpopHeadersForRequest, extractDpopNonceFromHeaders, type RequestDpopOptions } from '../dpop/dpop'
import { authorizationServerRequestWithDpopRetry } from '../dpop/dpop-retry'
import { Oauth2ClientErrorResponseError } from '../error/Oauth2ClientErrorResponseError'
import { Oauth2Error } from '../error/Oauth2Error'
import type { AuthorizationServerMetadata } from '../metadata/authorization-server/z-authorization-server-metadata'
import {
  authorizationCodeGrantIdentifier,
  clientCredentialsGrantIdentifier,
  getGrantTypesSupported,
  preAuthorizedCodeGrantIdentifier,
  refreshTokenGrantIdentifier,
} from '../z-grant-type'
import {
  type AccessTokenRequest,
  type AccessTokenResponse,
  zAccessTokenErrorResponse,
  zAccessTokenRequest,
  zAccessTokenResponse,
} from './z-access-token'

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
  callbacks: Pick<CallbackContext, 'fetch' | 'generateRandom' | 'hash' | 'signJwt' | 'clientAuthentication'>

  /**
   * The resource to which access is being requested. This can help the authorization
   * server in determining the resource server to handle the authorization request for
   */
  resource?: string

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
    resource: options.resource,
    ...options.additionalRequestPayload,
  } satisfies AccessTokenRequest

  return retrieveAccessToken({
    authorizationServerMetadata: options.authorizationServerMetadata,
    request,
    dpop: options.dpop,
    callbacks: options.callbacks,
    resource: options.resource,
  })
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
    resource: options.resource,
    ...options.additionalRequestPayload,
  } satisfies AccessTokenRequest

  return retrieveAccessToken({
    authorizationServerMetadata: options.authorizationServerMetadata,
    request,
    dpop: options.dpop,
    resource: options.resource,
    callbacks: options.callbacks,
  })
}

export interface RetrieveRefreshTokenAccessTokenOptions extends RetrieveAccessTokenBaseOptions {
  /**
   * The refresh token
   */
  refreshToken: string

  /**
   * Additional payload to include in the access token request. Items will be encoded and sent
   * using x-www-form-urlencoded format. Nested items (JSON) will be stringified and url encoded.
   */
  additionalRequestPayload?: Record<string, unknown>
}

export async function retrieveRefreshTokenAccessToken(
  options: RetrieveRefreshTokenAccessTokenOptions
): Promise<RetrieveAccessTokenReturn> {
  const request = {
    grant_type: refreshTokenGrantIdentifier,
    refresh_token: options.refreshToken,
    resource: options.resource,
    ...options.additionalRequestPayload,
  } satisfies AccessTokenRequest

  return retrieveAccessToken({
    authorizationServerMetadata: options.authorizationServerMetadata,
    request,
    dpop: options.dpop,
    callbacks: options.callbacks,
    resource: options.resource,
  })
}

export interface RetrieveClientCredentialsAccessTokenOptions extends RetrieveAccessTokenBaseOptions {
  /**
   * The scope of the access request
   */
  scope?: string

  /**
   * Additional payload to include in the access token request. Items will be encoded and sent
   * using x-www-form-urlencoded format. Nested items (JSON) will be stringified and url encoded.
   */
  additionalRequestPayload?: Record<string, unknown>
}

export async function retrieveClientCredentialsAccessToken(
  options: RetrieveClientCredentialsAccessTokenOptions
): Promise<RetrieveAccessTokenReturn> {
  const request = {
    grant_type: clientCredentialsGrantIdentifier,
    scope: options.scope,
    resource: options.resource,
    ...options.additionalRequestPayload,
  } satisfies AccessTokenRequest

  return retrieveAccessToken({
    authorizationServerMetadata: options.authorizationServerMetadata,
    request,
    dpop: options.dpop,
    callbacks: options.callbacks,
    resource: options.resource,
  })
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
  const fetchWithZod = createZodFetcher(options.callbacks.fetch)

  const accessTokenRequest = parseWithErrorHandling(
    zAccessTokenRequest,
    options.request,
    'Error validating access token request'
  )

  const supportedGrantTypes = getGrantTypesSupported(options.authorizationServerMetadata.grant_types_supported)
  if (!supportedGrantTypes.includes(accessTokenRequest.grant_type)) {
    throw new Oauth2Error(
      `The authorization server '${options.authorizationServerMetadata.issuer}' does not support the '${accessTokenRequest.grant_type}' grant type. Supported grant types are: ${supportedGrantTypes.join(', ')}`
    )
  }

  // For backwards compat with draft 11 (we send both)
  if (accessTokenRequest.tx_code) {
    accessTokenRequest.user_pin = accessTokenRequest.tx_code
  }

  return await authorizationServerRequestWithDpopRetry({
    dpop: options.dpop,
    request: async (dpop) => {
      const dpopHeaders = dpop
        ? await createDpopHeadersForRequest({
            request: {
              method: 'POST',
              url: options.authorizationServerMetadata.token_endpoint,
            },
            signer: dpop.signer,
            callbacks: options.callbacks,
            nonce: dpop.nonce,
          })
        : undefined

      const headers = new Headers({
        'Content-Type': ContentType.XWwwFormUrlencoded,
        ...dpopHeaders,
      })

      // Apply client authentication
      await options.callbacks.clientAuthentication({
        url: options.authorizationServerMetadata.token_endpoint,
        method: 'POST',
        authorizationServerMetadata: options.authorizationServerMetadata,
        body: accessTokenRequest,
        contentType: ContentType.XWwwFormUrlencoded,
        headers,
      })

      const { response, result } = await fetchWithZod(
        zAccessTokenResponse,
        ContentType.Json,
        options.authorizationServerMetadata.token_endpoint,
        {
          body: objectToQueryParams(accessTokenRequest).toString(),
          method: 'POST',
          headers,
        }
      )

      if (!response.ok || !result) {
        const tokenErrorResponse = zAccessTokenErrorResponse.safeParse(
          await response
            .clone()
            .json()
            .catch(() => null)
        )
        if (tokenErrorResponse.success) {
          throw new Oauth2ClientErrorResponseError(
            `Unable to retrieve access token from '${options.authorizationServerMetadata.token_endpoint}'. Received token error response with status ${response.status}`,
            tokenErrorResponse.data,
            response
          )
        }

        throw new InvalidFetchResponseError(
          `Unable to retrieve access token from '${options.authorizationServerMetadata.token_endpoint}'. Received response with status ${response.status}`,
          await response.clone().text(),
          response
        )
      }

      if (!result.success) {
        throw new ValidationError('Error validating access token response', result.error)
      }

      const dpopNonce = extractDpopNonceFromHeaders(response.headers) ?? undefined
      return {
        dpop: dpop
          ? {
              ...dpop,
              nonce: dpopNonce,
            }
          : undefined,
        accessTokenResponse: result.data,
      }
    },
  })
}
