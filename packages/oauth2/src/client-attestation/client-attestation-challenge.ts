import {
  ContentType,
  createZodFetcher,
  type FetchHeaders,
  InvalidFetchResponseError,
  ValidationError,
} from '@openid4vc/utils'
import type { CallbackContext } from '../callbacks'
import { Oauth2ErrorCodes, type Oauth2ErrorResponse } from '../common/z-oauth2-error'
import { Oauth2ClientErrorResponseError } from '../error/Oauth2ClientErrorResponseError'
import { Oauth2Error } from '../error/Oauth2Error'
import type { AuthorizationServerMetadata } from '../metadata/authorization-server/z-authorization-server-metadata'
import { oauthClientAttestationChallengeHeader, zClientAttestationChallengeResponse } from './z-client-attestation'

export interface RequestClientAttestationChallengeOptions {
  /**
   * Metadata of the authorization server from which to request the challenge.
   */
  authorizationServerMetadata: AuthorizationServerMetadata

  /**
   * Callback context
   */
  callbacks: Pick<CallbackContext, 'fetch'>
}

/**
 * Request a fresh Client Attestation challenge from the authorization server's `challenge_endpoint`.
 *
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-09.html#section-6.1
 *
 * @throws {Oauth2Error} if the authorization server has no `challenge_endpoint`
 * @throws {InvalidFetchResponseError} if the request failed
 * @throws {ValidationError} if the response could not be validated
 */
export async function requestClientAttestationChallenge(options: RequestClientAttestationChallengeOptions) {
  const fetchWithZod = createZodFetcher(options.callbacks.fetch)

  const { authorizationServerMetadata } = options
  const challengeEndpoint = authorizationServerMetadata.challenge_endpoint
  if (!challengeEndpoint) {
    throw new Oauth2Error(
      `Unable to request client attestation challenge. Authorization server '${authorizationServerMetadata.issuer}' has no 'challenge_endpoint'`
    )
  }

  const { response, result } = await fetchWithZod(
    zClientAttestationChallengeResponse,
    ContentType.Json,
    challengeEndpoint,
    {
      method: 'POST',
    }
  )

  if (!response.ok || !result) {
    throw new InvalidFetchResponseError(
      `Unable to request client attestation challenge from challenge endpoint '${challengeEndpoint}'. Received response with status ${response.status}`,
      await response.clone().text(),
      response
    )
  }

  if (!result.success) {
    throw new ValidationError('Error validating client attestation challenge response', result.error)
  }

  return {
    challenge: result.data.attestation_challenge,
  }
}

/**
 * Extract the Client Attestation challenge from the `OAuth-Client-Attestation-Challenge` response header.
 */
export function extractClientAttestationChallengeFromHeaders(headers: FetchHeaders) {
  return headers.get(oauthClientAttestationChallengeHeader)
}

export interface ShouldRetryAuthorizationServerRequestWithClientAttestationChallengeOptions {
  /**
   * The error response that will be evaluated for the 'use_attestation_challenge' error to determine
   * whether the request should be retried using a fresh client attestation challenge.
   */
  errorResponse: Oauth2ErrorResponse

  /**
   * The headers returned in the response. The 'OAuth-Client-Attestation-Challenge' header will be
   * extracted if the error response indicates so. Will throw an error if the 'error' in the response is
   * 'use_attestation_challenge' but the headers do not contain the 'OAuth-Client-Attestation-Challenge'
   * header value.
   */
  responseHeaders: FetchHeaders
}

export function shouldRetryAuthorizationServerRequestWithClientAttestationChallenge(
  options: ShouldRetryAuthorizationServerRequestWithClientAttestationChallengeOptions
) {
  if (options.errorResponse.error !== Oauth2ErrorCodes.UseAttestationChallenge) {
    return {
      retry: false,
    } as const
  }

  const attestationChallenge = extractClientAttestationChallengeFromHeaders(options.responseHeaders)
  if (!attestationChallenge) {
    throw new Oauth2Error(
      `Error response error contains error '${Oauth2ErrorCodes.UseAttestationChallenge}' but the response headers do not include a valid '${oauthClientAttestationChallengeHeader}' header value.`
    )
  }

  return {
    retry: true,
    attestationChallenge,
  } as const
}

/**
 * Wraps an authorization server request so that it is retried once with a fresh Client Attestation
 * challenge when the server responds with the 'use_attestation_challenge' error and provides a
 * challenge in the 'OAuth-Client-Attestation-Challenge' response header.
 *
 * Mirrors {@link authorizationServerRequestWithDpopRetry} for DPoP nonces.
 */
export async function authorizationServerRequestWithClientAttestationChallengeRetry<T>(options: {
  request: (attestationChallenge?: string) => Promise<T>
}): Promise<T> {
  try {
    return await options.request()
  } catch (error) {
    if (error instanceof Oauth2ClientErrorResponseError) {
      const challengeRetry = shouldRetryAuthorizationServerRequestWithClientAttestationChallenge({
        responseHeaders: error.response.headers,
        errorResponse: error.errorResponse,
      })

      // Retry with the fresh challenge
      if (challengeRetry.retry) {
        return options.request(challengeRetry.attestationChallenge)
      }
    }

    throw error
  }
}
