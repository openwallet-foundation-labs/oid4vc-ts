import {
  ContentType,
  ValidationError,
  createZodFetcher,
  objectToQueryParams,
  parseWithErrorHandling,
} from '@openid4vc/utils'
import { InvalidFetchResponseError } from '@openid4vc/utils'
import type { CallbackContext } from '../callbacks'
import {
  type RequestClientAttestationOptions,
  createClientAttestationForRequest,
} from '../client-attestation/client-attestation-pop'
import { type RequestDpopOptions, createDpopHeadersForRequest, extractDpopNonceFromHeaders } from '../dpop/dpop'
import { authorizationServerRequestWithDpopRetry } from '../dpop/dpop-retry'
import { Oauth2ClientAuthorizationChallengeError } from '../error/Oauth2ClientAuthorizationChallengeError'
import { Oauth2Error } from '../error/Oauth2Error'
import type { AuthorizationServerMetadata } from '../metadata/authorization-server/z-authorization-server-metadata'
import { createPkce } from '../pkce'
import {
  type AuthorizationChallengeRequest,
  zAuthorizationChallengeErrorResponse,
  zAuthorizationChallengeRequest,
  zAuthorizationChallengeResponse,
} from './z-authorization-challenge'

export interface SendAuthorizationChallengeRequestOptions {
  /**
   * Callback context
   */
  callbacks: Pick<CallbackContext, 'fetch' | 'hash' | 'generateRandom' | 'signJwt'>

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

  /**
   * If client attestation needs to be included in the request.
   */
  clientAttestation?: RequestClientAttestationOptions

  /**
   * DPoP options
   */
  dpop?: RequestDpopOptions
}

/**
 * Send an authorization challenge request.
 *
 * @throws {Oauth2ClientAuthorizationChallengeError} if the request failed and a {@link AuthorizationChallengeErrorResponse} is returned
 * @throws {InvalidFetchResponseError} if the request failed but no error response could be parsed
 * @throws {ValidationError} if a successful response was received but an error occured during verification of the {@link AuthorizationChallengeResponse}
 */
export async function sendAuthorizationChallengeRequest(options: SendAuthorizationChallengeRequestOptions) {
  const fetchWithZod = createZodFetcher(options.callbacks.fetch)

  const authorizationServerMetadata = options.authorizationServerMetadata
  const authorizationChallengeEndpoint = authorizationServerMetadata.authorization_challenge_endpoint
  if (!authorizationChallengeEndpoint) {
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

  const clientAttestation = options.clientAttestation
    ? await createClientAttestationForRequest({
        authorizationServer: options.authorizationServerMetadata.issuer,
        clientAttestation: options.clientAttestation,
        callbacks: options.callbacks,
      })
    : undefined

  const authorizationChallengeRequest = parseWithErrorHandling(zAuthorizationChallengeRequest, {
    ...options.additionalRequestPayload,
    auth_session: options.authSession,
    client_id: options.clientId,
    scope: options.scope,
    resource: options.resource,
    code_challenge: pkce?.codeChallenge,
    code_challenge_method: pkce?.codeChallengeMethod,
    presentation_during_issuance_session: options.presentationDuringIssuanceSession,
    ...clientAttestation?.body,
  } satisfies AuthorizationChallengeRequest)

  return authorizationServerRequestWithDpopRetry({
    dpop: options.dpop,
    request: async (dpop) => {
      const dpopHeaders = dpop
        ? await createDpopHeadersForRequest({
            request: {
              method: 'POST',
              url: authorizationChallengeEndpoint,
            },
            signer: dpop.signer,
            callbacks: options.callbacks,
            nonce: dpop.nonce,
          })
        : undefined

      const { response, result } = await fetchWithZod(
        zAuthorizationChallengeResponse,
        ContentType.Json,
        authorizationChallengeEndpoint,
        {
          method: 'POST',
          body: objectToQueryParams(authorizationChallengeRequest).toString(),
          headers: {
            ...clientAttestation?.headers,
            ...dpopHeaders,
            'Content-Type': ContentType.XWwwFormUrlencoded,
          },
        }
      )

      if (!response.ok || !result) {
        const authorizationChallengeErrorResponse = zAuthorizationChallengeErrorResponse.safeParse(
          await response
            .clone()
            .json()
            .catch(() => null)
        )
        if (authorizationChallengeErrorResponse.success) {
          throw new Oauth2ClientAuthorizationChallengeError(
            `Error requesting authorization code from authorization challenge endpoint '${authorizationServerMetadata.authorization_challenge_endpoint}'. Received response with status ${response.status}`,
            authorizationChallengeErrorResponse.data,
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
        throw new ValidationError('Error validating authorization challenge response', result.error)
      }

      const dpopNonce = extractDpopNonceFromHeaders(response.headers) ?? undefined
      return {
        pkce,
        dpop: dpop
          ? {
              ...dpop,
              nonce: dpopNonce,
            }
          : undefined,
        authorizationChallengeResponse: result.data,
      }
    },
  })
}
