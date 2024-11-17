import { ContentType, type Fetch, createValibotFetcher, objectToQueryParams } from '@animo-id/oauth2-utils'
import { InvalidFetchResponseError } from '@animo-id/oauth2-utils'
import * as v from 'valibot'
import { ValidationError } from '../../../utils/src/error/ValidationError'
import { vAccessTokenErrorResponse } from '../access-token/v-access-token'
import type { CallbackContext } from '../callbacks'
import { Oauth2ClientErrorResponseError } from '../error/Oauth2ClientErrorResponseError'
import { Oauth2Error } from '../error/Oauth2Error'
import type { AuthorizationServerMetadata } from '../metadata/authorization-server/v-authorization-server-metadata'
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
   * Metadata of the authorization server for which to create the authorization request url
   */
  authorizationServerMetadata: AuthorizationServerMetadata

  /**
   * The client id to use for the authorization request
   */
  clientId: string

  /**
   * Scope to request for the authorization request
   */
  scope?: string

  /**
   * The resource to which access is being requested. This can help the authorization
   * server in determining the resource server to handle the authorization request for
   */
  resource?: string

  /**
   * Redirect uri to include in the authorization request
   */
  redirectUri?: string

  /**
   * Additional payload to include in the authorization request. Items will be encoded and sent
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
  const authorizationServerMetadata = options.authorizationServerMetadata

  if (!authorizationServerMetadata.authorization_endpoint) {
    throw new Oauth2Error(
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
    resource: options.resource,
    scope: options.scope,
    code_challenge: pkce?.codeChallenge,
    code_challenge_method: pkce?.codeChallengeMethod,
  }
  let pushedAuthorizationRequest: PushedAuthorizationRequest | undefined = undefined

  if (
    authorizationServerMetadata.require_pushed_authorization_requests ||
    authorizationServerMetadata.pushed_authorization_request_endpoint
  ) {
    // Use PAR if supported or required
    if (!authorizationServerMetadata.pushed_authorization_request_endpoint) {
      throw new Oauth2Error(
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

  const authorizationRequestUrl = `${authorizationServerMetadata.authorization_endpoint}?${objectToQueryParams(pushedAuthorizationRequest ?? authorizationRequest).toString()}`
  return {
    authorizationRequestUrl,
    pkce,
  }
}

interface PushAuthorizationRequestOptions {
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
    throw new Oauth2Error(
      `Authorization request contains 'request_uri' parameter. This is not allowed for pushed authorization reuqests.`
    )
  }

  const { response, result } = await fetchWithValibot(
    vPushedAuthorizationResponse,
    ContentType.Json,
    options.pushedAuthorizationRequestEndpoint,
    {
      method: 'POST',
      body: objectToQueryParams(options.authorizationRequest).toString(),
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
      throw new Oauth2ClientErrorResponseError(
        `Unable to push authorization request to '${options.pushedAuthorizationRequestEndpoint}'. Received response with status ${response.status}`,
        parErrorResponse.output,
        response
      )
    }

    throw new InvalidFetchResponseError(
      `Unable to push authorization request to '${options.pushedAuthorizationRequestEndpoint}'. Received response with status ${response.status}`,
      await response.clone().text(),
      response
    )
  }

  if (!result.success) {
    throw new ValidationError('Error validating pushed authorization response', result.issues)
  }

  return result.output
}
