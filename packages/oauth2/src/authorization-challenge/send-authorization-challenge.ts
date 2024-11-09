import {
  ContentType,
  ValidationError,
  createValibotFetcher,
  objectToQueryParams,
  parseWithErrorHandling,
} from '@animo-id/oauth2-utils'
import { InvalidFetchResponseError } from '@animo-id/oauth2-utils'
import * as v from 'valibot'
import type { CallbackContext } from '../callbacks'
import { Oauth2ClientAuthorizationChallengeError } from '../error/Oauth2ClientAuthorizationChallengeError'
import { Oauth2Error } from '../error/Oauth2Error'
import type { AuthorizationServerMetadata } from '../metadata/authorization-server/v-authorization-server-metadata'
import { createPkce } from '../pkce'
import {
  type AuthorizationChallengeRequest,
  vAuthorizationChallengeErrorResponse,
  vAuthorizationChallengeRequest,
  vAuthorizationChallengeResponse,
} from './v-authorization-challenge'

export interface SendAuthorizationChallengeRequestOptions {
  /**
   * Callback context
   */
  callbacks: Pick<CallbackContext, 'fetch' | 'hash' | 'generateRandom'>

  /**
   * Metadata of the authorization server where to perform the authorization challenge
   */
  authorizationServerMetadata: AuthorizationServerMetadata

  /**
   * Previously established auth session
   */
  authSession?: string

  /**
   * The client id to use for the authorization challenge request
   */
  clientId?: string

  /**
   * Scope to request for the authorization challenge request
   */
  scope?: string

  /**
   * The resource to which access is being requested. This can help the authorization
   * server in determining the resource server to handle the authorization request for
   */
  resource?: string

  /**
   * Presentation during issuance sessios if credentials were presented
   * as part of an issuance session
   */
  presentationDuringIssuanceSession?: string

  /**
   * Additional payload to include in the authorization challenge request. Items will be encoded and sent
   * using x-www-form-urlencoded format. Nested items (JSON) will be stringified and url encoded.
   */
  additionalRequestPayload?: Record<string, unknown>

  /**
   * Code verifier to use for pkce. If not provided a value will generated when pkce is supported
   */
  pkceCodeVerifier?: string
}

/**
 * Send an authorization challenge request.
 *
 * @throws {Oauth2ClientAuthorizationChallengeError} if the request failed and a {@link AuthorizationChallengeErrorResponse} is returned
 * @throws {InvalidFetchResponseError} if the request failed but no error response could be parsed
 * @throws {ValidationError} if a successful response was received but an error occured during verification of the {@link AuthorizationChallengeResponse}
 */
export async function sendAuthorizationChallengeRequest(options: SendAuthorizationChallengeRequestOptions) {
  const fetchWithValibot = createValibotFetcher(options.callbacks.fetch)

  const authorizationServerMetadata = options.authorizationServerMetadata
  if (!authorizationServerMetadata.authorization_challenge_endpoint) {
    throw new Oauth2Error(
      `Unable to send authorization challange. Authorization server '${authorizationServerMetadata.issuer}' has no 'authorization_challenge_endpoint'`
    )
  }

  // PKCE
  // If auth session is included it's likely not needed to use PKCE
  const pkce =
    authorizationServerMetadata.code_challenge_methods_supported && !options.authSession
      ? await createPkce({
          allowedCodeChallengeMethods: authorizationServerMetadata.code_challenge_methods_supported,
          callbacks: options.callbacks,
          codeVerifier: options.pkceCodeVerifier,
        })
      : undefined

  const authorizationChallengeRequest = parseWithErrorHandling(vAuthorizationChallengeRequest, {
    ...options.additionalRequestPayload,
    auth_session: options.authSession,
    client_id: options.clientId,
    scope: options.scope,
    resource: options.resource,
    code_challenge: pkce?.codeChallenge,
    code_challenge_method: pkce?.codeChallengeMethod,
    presentation_during_issuance_session: options.presentationDuringIssuanceSession,
  } satisfies AuthorizationChallengeRequest)

  const { response, result } = await fetchWithValibot(
    vAuthorizationChallengeResponse,
    ContentType.Json,
    authorizationServerMetadata.authorization_challenge_endpoint,
    {
      method: 'POST',
      body: objectToQueryParams(authorizationChallengeRequest),
      headers: {
        'Content-Type': ContentType.XWwwFormUrlencoded,
      },
    }
  )

  if (!response.ok || !result) {
    const authorizationChallengeErrorResponse = v.safeParse(
      vAuthorizationChallengeErrorResponse,
      await response
        .clone()
        .json()
        .catch(() => null)
    )
    if (authorizationChallengeErrorResponse.success) {
      throw new Oauth2ClientAuthorizationChallengeError(
        `Error requesting authorization code from authorization challenge endpoint '${authorizationServerMetadata.authorization_challenge_endpoint}'. Received response with status ${response.status}`,
        authorizationChallengeErrorResponse.output,
        response
      )
    }

    throw new InvalidFetchResponseError(
      `Error requesting authorization code from authorization challenge endpoint '${authorizationServerMetadata.authorization_challenge_endpoint}'. Received response with status ${response.status}`,
      await response.clone().text(),
      response
    )
  }

  if (!result.success) {
    throw new ValidationError('Error validating authorization challenge response', result.issues)
  }

  return { pkce, authorizationChallengeResponse: result.output }
}
