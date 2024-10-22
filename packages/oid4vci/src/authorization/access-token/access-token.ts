import * as v from 'valibot'
import { ContentType } from '../../common/content-type'
import {
  authorizationCodeGrantIdentifier,
  preAuthorizedCodeGrantIdentifier,
} from '../../credential-offer/v-credential-offer'
import { Oid4vcInvalidFetchResponseError } from '../../error/Oid4vcInvalidFetchResponseError'
import { Oid4vcOauthErrorResponseError } from '../../error/Oid4vcOauthErrorResponseError'
import { Oid4vcValidationError } from '../../error/Oid4vcValidationError'
import { getAuthorizationServerMetadataFromList } from '../../metadata/authorization-server/authorization-server-metadata'
import type { IssuerMetadataResult } from '../../metadata/fetch-issuer-metadata'
import { objectToQueryParams } from '../../utils/url'
import { type Fetch, createValibotFetcher } from '../../utils/valibot-fetcher'
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

export interface RetrievePreAuthorizedCodeAccessTokenOptions {
  /**
   * Custom fetch implementation to use
   */
  fetch?: Fetch

  /**
   * The issuer identifier of the authorization server to use.
   */
  authorizationServer: string

  /**
   * Metadata of the credential issuer and authorization servers.
   */
  issuerMetadata: IssuerMetadataResult

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
): Promise<AccessTokenResponse> {
  const request = {
    grant_type: preAuthorizedCodeGrantIdentifier,
    'pre-authorized_code': options.preAuthorizedCode,
    tx_code: options.txCode,
  } satisfies AccessTokenRequest

  const accessTokenResponse = await retrieveAccessToken({
    authorizationServer: options.authorizationServer,
    issuerMetadata: options.issuerMetadata,
    request,
    fetch: options.fetch,
  })

  return accessTokenResponse
}

export interface RetrieveAuthorizationCodeAccessTokenOptions {
  /**
   * Custom fetch implementation to use
   */
  fetch?: Fetch

  /**
   * The issuer identifier of the authorization server to use.
   */
  authorizationServer: string

  /**
   * Metadata of the credential issuer and authorization servers.
   */
  issuerMetadata: IssuerMetadataResult

  /**
   * PKCE Code verifier that was used in the authorization request.
   */
  pkceCodeVerifier: string

  /**
   * The authorization code
   */
  authorizationCode: string

  /**
   * Additional payload to include in the access token request. Items will be encoded and sent
   * using x-www-form-urlencoded format. Nested items (JSON) will be stringified and url encoded.
   */
  additionalRequestPayload?: Record<string, unknown>
}

export async function retrieveAuthorizationCodeAccessToken(
  options: RetrieveAuthorizationCodeAccessTokenOptions
): Promise<AccessTokenResponse> {
  const request = {
    ...options.additionalRequestPayload,
    grant_type: authorizationCodeGrantIdentifier,
    code: options.authorizationCode,
    code_verifier: options.pkceCodeVerifier,
  } satisfies AccessTokenRequest

  const accessTokenResponse = await retrieveAccessToken({
    authorizationServer: options.authorizationServer,
    issuerMetadata: options.issuerMetadata,
    request,
    fetch: options.fetch,
  })

  return accessTokenResponse
}

interface RetrieveAccessTokenOptions {
  /**
   * Custom fetch implementation to use
   */
  fetch?: Fetch

  /**
   * The issuer identifier of the authorization server to use.
   */
  authorizationServer: string

  /**
   * Metadata of the credential issuer and authorization servers.
   */
  issuerMetadata: IssuerMetadataResult

  /**
   * The access token request body
   */
  request: AccessTokenRequest
}

/**
 * Internal method
 */
async function retrieveAccessToken(options: RetrieveAccessTokenOptions): Promise<AccessTokenResponse> {
  const fetchWithValibot = createValibotFetcher(options.fetch)

  const authorizationServerMetadata = getAuthorizationServerMetadataFromList(
    options.issuerMetadata.authorizationServers,
    options.authorizationServer
  )

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
      },
    }
  )

  if (!response.ok || !result) {
    const tokenErrorResponse = v.safeParse(vAccessTokenErrorResponse, await response.clone().json())
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

  // TODO: probably good to also return the response? At least status/headers
  return result.output
}
