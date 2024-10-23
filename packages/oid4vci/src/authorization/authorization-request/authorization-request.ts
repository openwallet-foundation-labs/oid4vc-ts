import * as v from 'valibot'
import type { CallbackContext } from '../../callbacks'
import { ContentType } from '../../common/content-type'
import { Oid4vcError } from '../../error/Oid4vcError'
import { Oid4vcInvalidFetchResponseError } from '../../error/Oid4vcInvalidFetchResponseError'
import { Oid4vcOauthErrorResponseError } from '../../error/Oid4vcOauthErrorResponseError'
import { Oid4vcValidationError } from '../../error/Oid4vcValidationError'
import type { Fetch } from '../../globals'
import { getAuthorizationServerMetadataFromList } from '../../metadata/authorization-server/authorization-server-metadata'
import type { IssuerMetadataResult } from '../../metadata/fetch-issuer-metadata'
import { objectToQueryParams } from '../../utils/url'
import { createValibotFetcher } from '../../utils/valibot-fetcher'
import { vAccessTokenErrorResponse } from '../access-token/v-access-token'
import { createPkce } from '../pkce'
import {
  type AuthorizationRequest,
  type PushedAuthorizationRequest,
  vPushedAuthorizationResponse,
} from './v-authorization-request'

export interface CreateAuthorizationRequestUrlOptions {
  /**
   * Callback context mostly for crypto related functionality
   */
  callbacks: Pick<CallbackContext, 'fetch' | 'hash' | 'generateRandom'>

  /**
   * The issuer identifier of the authorization server to use.
   */
  authorizationServer: string

  /**
   * Metadata of the credential issuer and authorization servers.
   */
  issuerMetadata: IssuerMetadataResult

  /**
   * Optional issuer_state from the credential offer if authorization request was initiated
   * from an offer.
   */
  issuerState?: string

  /**
   * The client id to use for the authorization request
   */
  clientId: string

  /**
   * Scope to request for the authorization request
   */
  scope?: string

  /**
   * Redirect uri to include in the authorization request
   */
  redirectUri?: string

  /**
   * Additional payload to include in the authorizatino request. Items will be encoded and sent
   * using x-www-form-urlencoded format. Nested items (JSON) will be stringified and url encoded.
   */
  additionalRequestPayload?: Record<string, unknown>

  /**
   * Code verifier to use for pkce. If not provided a value will generated when pkce is supported
   */
  pkceCodeVerifier?: string
}

/**
 * Create an authorization request url that can be used for authorization.
 *
 * If the authorization server supports Pushed Authorization Requests (PAR) the
 * request will first be pushed to the authorization request, and a reference to
 * the authorization request will be returned (using the 'request_uri' param).
 */
export async function createAuthorizationRequestUrl(options: CreateAuthorizationRequestUrlOptions) {
  const authorizationServerMetadata = getAuthorizationServerMetadataFromList(
    options.issuerMetadata.authorizationServers,
    options.authorizationServer
  )

  if (!authorizationServerMetadata.authorization_endpoint) {
    throw new Oid4vcError(
      `Unable to create authorization request url. Authorization server '${authorizationServerMetadata.issuer}' has no 'authorization_endpoint'`
    )
  }

  // PKCE
  const pkce = authorizationServerMetadata.code_challenge_methods_supported
    ? await createPkce({
        allowedCodeChallengeMethods: authorizationServerMetadata.code_challenge_methods_supported,
        callbacks: options.callbacks,
        codeVerifier: options.pkceCodeVerifier,
      })
    : undefined

  const authorizationRequest: AuthorizationRequest = {
    ...options.additionalRequestPayload,
    response_type: 'code',
    client_id: options.clientId,
    redirect_uri: options.redirectUri,
    scope: options.scope,
    code_challenge: pkce?.codeChallenge,
    code_challenge_method: pkce?.codeChallengeMethod,
    issuer_state: options.issuerState,
  }
  let pushedAuthorizationRequest: PushedAuthorizationRequest | undefined = undefined

  // Use PAR if supported or required
  if (
    authorizationServerMetadata.require_pushed_authorization_requests ||
    authorizationServerMetadata.pushed_authorization_request_endpoint
  ) {
    if (!authorizationServerMetadata.pushed_authorization_request_endpoint) {
      throw new Oid4vcError(
        `Authorization server '${authorizationServerMetadata.issuer}' indicated that pushed authorization requests are required, but the 'pushed_authorization_request_endpoint' is missing in the authorization server metadata.`
      )
    }

    const { request_uri } = await pushAuthorizationRequest({
      authorizationRequest,
      pushedAuthorizationRequestEndpoint: authorizationServerMetadata.pushed_authorization_request_endpoint,
      fetch: options.callbacks.fetch,
    })

    pushedAuthorizationRequest = {
      request_uri,
      client_id: authorizationRequest.client_id,
    }
  }

  const authorizationRequestUrl = `${authorizationServerMetadata.authorization_endpoint}?${objectToQueryParams(pushedAuthorizationRequest ?? authorizationRequest)}`
  return {
    authorizationRequestUrl,
    pkce,
    authorizationServer: authorizationServerMetadata.issuer,
  }
}

export interface PushAuthorizationRequestOptions {
  pushedAuthorizationRequestEndpoint: string
  authorizationRequest: AuthorizationRequest

  /**
   * Custom fetch implementation to use
   */
  fetch?: Fetch
}

async function pushAuthorizationRequest(options: PushAuthorizationRequestOptions) {
  const fetchWithValibot = createValibotFetcher(options.fetch)

  if (options.authorizationRequest.request_uri) {
    throw new Oid4vcError(
      `Authorization request contains 'request_uri' parameter. This is not allowed for pushed authorization reuqests.`
    )
  }

  const { response, result } = await fetchWithValibot(
    vPushedAuthorizationResponse,
    options.pushedAuthorizationRequestEndpoint,
    {
      method: 'POST',
      body: objectToQueryParams(options.authorizationRequest),
      headers: {
        'Content-Type': ContentType.XWwwFormUrlencoded,
      },
    }
  )

  if (!response.ok || !result) {
    const parErrorResponse = v.safeParse(
      vAccessTokenErrorResponse,
      await response
        .clone()
        .json()
        .catch(() => null)
    )
    if (parErrorResponse.success) {
      throw new Oid4vcOauthErrorResponseError(
        `Unable to push authorization request to '${options.pushedAuthorizationRequestEndpoint}'. Received response with status ${response.status}`,
        parErrorResponse.output,
        response
      )
    }

    throw new Oid4vcInvalidFetchResponseError(
      `Unable to push authorization request to '${options.pushedAuthorizationRequestEndpoint}'. Received response with status ${response.status}`,
      await response.clone().text(),
      response
    )
  }

  if (!result.success) {
    throw new Oid4vcValidationError('Error validating pushed authorization response', result.issues)
  }

  return result.output
}
