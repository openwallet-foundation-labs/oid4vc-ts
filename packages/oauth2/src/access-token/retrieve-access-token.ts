import { ContentType, createZodFetcher, objectToQueryParams, parseWithErrorHandling } from '@openid4vc/utils'
import { InvalidFetchResponseError } from '@openid4vc/utils'
import { ValidationError } from '../../../utils/src/error/ValidationError'
import type { CallbackContext } from '../callbacks'
import {
  type RequestClientAttestationOptions,
  createClientAttestationForRequest,
} from '../client-attestation/client-attestation-pop'
import { type RequestDpopOptions, createDpopHeadersForRequest, extractDpopNonceFromHeaders } from '../dpop/dpop'
import { authorizationServerRequestWithDpopRetry } from '../dpop/dpop-retry'
import { Oauth2ClientErrorResponseError } from '../error/Oauth2ClientErrorResponseError'
import type { AuthorizationServerMetadata } from '../metadata/authorization-server/v-authorization-server-metadata'
import {
  authorizationCodeGrantIdentifier,
  preAuthorizedCodeGrantIdentifier,
  refreshTokenGrantIdentifier,
} from '../v-grant-type'
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

  /**
   * If client attestation needs to be included in the request.
   */
  clientAttestation?: RequestClientAttestationOptions
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
    clientAttestation: options.clientAttestation,
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
    clientAttestation: options.clientAttestation,
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
    clientAttestation: options.clientAttestation,
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
    vAccessTokenRequest,
    options.request,
    'Error validating access token request'
  )

  // For backwards compat with draft 11 (we send both)
  if (accessTokenRequest.tx_code) {
    accessTokenRequest.user_pin = accessTokenRequest.tx_code
  }

  const clientAttestation = options.clientAttestation
    ? await createClientAttestationForRequest({
        authorizationServer: options.authorizationServerMetadata.issuer,
        clientAttestation: options.clientAttestation,
        callbacks: options.callbacks,
      })
    : undefined

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

      const requestQueryParams = objectToQueryParams({
        ...accessTokenRequest,
        ...clientAttestation?.body,
      })
      const { response, result } = await fetchWithZod(
        vAccessTokenResponse,
        ContentType.Json,
        options.authorizationServerMetadata.token_endpoint,
        {
          body: requestQueryParams.toString(),
          method: 'POST',
          headers: {
            'Content-Type': ContentType.XWwwFormUrlencoded,
            ...clientAttestation?.headers,
            ...dpopHeaders,
          },
        }
      )

      if (!response.ok || !result) {
        const tokenErrorResponse = vAccessTokenErrorResponse.safeParse(
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
