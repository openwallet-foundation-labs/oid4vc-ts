import { ContentType, type Fetch, createZodFetcher, objectToQueryParams } from '@openid4vc/utils'
import { InvalidFetchResponseError } from '@openid4vc/utils'
import { ValidationError } from '../../../utils/src/error/ValidationError'
import { type CallbackContext, HashAlgorithm } from '../callbacks'
import {
  type RequestClientAttestationOptions,
  createClientAttestationForRequest,
} from '../client-attestation/client-attestation-pop'
import { calculateJwkThumbprint } from '../common/jwk/jwk-thumbprint'
import { zOauth2ErrorResponse } from '../common/z-oauth2-error'
import { type RequestDpopOptions, createDpopHeadersForRequest, extractDpopNonceFromHeaders } from '../dpop/dpop'
import { authorizationServerRequestWithDpopRetry } from '../dpop/dpop-retry'
import { Oauth2ClientErrorResponseError } from '../error/Oauth2ClientErrorResponseError'
import { Oauth2Error } from '../error/Oauth2Error'
import type { AuthorizationServerMetadata } from '../metadata/authorization-server/z-authorization-server-metadata'
import { createPkce } from '../pkce'
import {
  type AuthorizationRequest,
  type PushedAuthorizationRequest,
  zPushedAuthorizationResponse,
} from './z-authorization-request'

export interface CreateAuthorizationRequestUrlOptions {
  /**
   * Callback context mostly for crypto related functionality
   */
  callbacks: Pick<CallbackContext, 'fetch' | 'hash' | 'generateRandom' | 'signJwt'>

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

  /**
   * If client attestation needs to be included in the request.
   *
   * Will ONLY be used if PAR is used.
   */
  clientAttestation?: RequestClientAttestationOptions

  /**
   * DPoP options
   *
   * If PAR is not used only the `dpop_jkt` property will be included in the request
   */
  dpop?: RequestDpopOptions
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

  const pushedAuthorizationRequestEndpoint = authorizationServerMetadata.pushed_authorization_request_endpoint
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
  let dpop: RequestDpopOptions | undefined = options.dpop

  if (authorizationServerMetadata.require_pushed_authorization_requests || pushedAuthorizationRequestEndpoint) {
    // Use PAR if supported or required
    if (!pushedAuthorizationRequestEndpoint) {
      throw new Oauth2Error(
        `Authorization server '${authorizationServerMetadata.issuer}' indicated that pushed authorization requests are required, but the 'pushed_authorization_request_endpoint' is missing in the authorization server metadata.`
      )
    }

    const clientAttestation = options.clientAttestation
      ? await createClientAttestationForRequest({
          authorizationServer: options.authorizationServerMetadata.issuer,
          clientAttestation: options.clientAttestation,
          callbacks: options.callbacks,
        })
      : undefined

    const { pushedAuthorizationResponse, dpopNonce } = await authorizationServerRequestWithDpopRetry({
      dpop: options.dpop,
      request: async (dpop) => {
        const dpopHeaders = dpop
          ? await createDpopHeadersForRequest({
              request: {
                method: 'POST',
                url: pushedAuthorizationRequestEndpoint,
              },
              signer: dpop.signer,
              callbacks: options.callbacks,
              nonce: dpop.nonce,
            })
          : undefined

        return await pushAuthorizationRequest({
          authorizationRequest,
          pushedAuthorizationRequestEndpoint,
          fetch: options.callbacks.fetch,
          headers: {
            // TODO: use client authentication for this
            ...clientAttestation?.headers,
            ...dpopHeaders,
          },
        })
      },
    })

    pushedAuthorizationRequest = {
      request_uri: pushedAuthorizationResponse.request_uri,
      client_id: authorizationRequest.client_id,
    }

    if (options.dpop && dpopNonce) {
      dpop = {
        ...options.dpop,
        nonce: dpopNonce,
      }
    }
  } else {
    // If not using PAR but dpop we include the `dpop_jkt` option
    if (options.dpop) {
      authorizationRequest.dpop_jkt = await calculateJwkThumbprint({
        hashAlgorithm: HashAlgorithm.Sha256,
        hashCallback: options.callbacks.hash,
        jwk: options.dpop.signer.publicJwk,
      })
    }
  }

  const authorizationRequestUrl = `${authorizationServerMetadata.authorization_endpoint}?${objectToQueryParams(pushedAuthorizationRequest ?? authorizationRequest).toString()}`
  return {
    authorizationRequestUrl,
    pkce,
    dpop,
  }
}

interface PushAuthorizationRequestOptions {
  pushedAuthorizationRequestEndpoint: string
  authorizationRequest: AuthorizationRequest

  /**
   * Headers to include in the PAR request
   */
  headers?: Record<string, unknown>

  /**
   * Custom fetch implementation to use
   */
  fetch?: Fetch
}

async function pushAuthorizationRequest(options: PushAuthorizationRequestOptions) {
  const fetchWithZod = createZodFetcher(options.fetch)

  if (options.authorizationRequest.request_uri) {
    throw new Oauth2Error(
      `Authorization request contains 'request_uri' parameter. This is not allowed for pushed authorization reuqests.`
    )
  }

  const { response, result } = await fetchWithZod(
    zPushedAuthorizationResponse,
    ContentType.Json,
    options.pushedAuthorizationRequestEndpoint,
    {
      method: 'POST',
      body: objectToQueryParams(options.authorizationRequest).toString(),
      headers: {
        ...options.headers,
        'Content-Type': ContentType.XWwwFormUrlencoded,
      },
    }
  )

  if (!response.ok || !result) {
    const parErrorResponse = zOauth2ErrorResponse.safeParse(
      await response
        .clone()
        .json()
        .catch(() => null)
    )
    if (parErrorResponse.success) {
      throw new Oauth2ClientErrorResponseError(
        `Unable to push authorization request to '${options.pushedAuthorizationRequestEndpoint}'. Received response with status ${response.status}`,
        parErrorResponse.data,
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
    throw new ValidationError('Error validating pushed authorization response', result.error)
  }

  const dpopNonce = extractDpopNonceFromHeaders(response.headers)
  return {
    dpopNonce,
    pushedAuthorizationResponse: result.data,
  }
}
