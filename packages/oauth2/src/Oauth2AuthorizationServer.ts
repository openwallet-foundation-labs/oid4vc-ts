import { type FetchHeaders, parseWithErrorHandling } from '@openid4vc/utils'
import { type CreateAccessTokenOptions, createAccessTokenJwt } from './access-token/create-access-token'
import {
  type CreateAccessTokenResponseOptions,
  createAccessTokenResponse,
} from './access-token/create-access-token-response'
import { type ParseAccessTokenRequestOptions, parseAccessTokenRequest } from './access-token/parse-access-token-request'
import {
  type VerifyAuthorizationCodeAccessTokenRequestOptions,
  type VerifyPreAuthorizedCodeAccessTokenRequestOptions,
  verifyAuthorizationCodeAccessTokenRequest,
  verifyPreAuthorizedCodeAccessTokenRequest,
} from './access-token/verify-access-token-request'
import {
  type CreateAuthorizationChallengeErrorResponseOptions,
  type CreateAuthorizationChallengeResponseOptions,
  createAuthorizationChallengeErrorResponse,
  createAuthorizationChallengeResponse,
} from './authorization-challenge/create-authorization-challenge-response'
import {
  type ParseAuthorizationChallengeRequestOptions,
  parseAuthorizationChallengeRequest,
} from './authorization-challenge/parse-authorization-challenge-request'
import type { CallbackContext } from './callbacks'
import {
  extractClientAttestationJwtsFromHeaders,
  verifyClientAttestationJwt,
} from './client-attestation/clent-attestation'
import { verifyClientAttestationPopJwt } from './client-attestation/client-attestation-pop'
import { Oauth2ErrorCodes } from './common/v-oauth2-error'
import {
  type AuthorizationServerMetadata,
  vAuthorizationServerMetadata,
} from './metadata/authorization-server/v-authorization-server-metadata'

export interface Oauth2AuthorizationServerOptions {
  /**
   * Callbacks required for the oauth2 authorization server
   */
  callbacks: CallbackContext
}

export class Oauth2AuthorizationServer {
  public constructor(private options: Oauth2AuthorizationServerOptions) {}

  public createAuthorizationServerMetadata(authorizationServerMetadata: AuthorizationServerMetadata) {
    return parseWithErrorHandling(
      vAuthorizationServerMetadata,
      authorizationServerMetadata,
      'Error validating authorization server metadata'
    )
  }

  /**
   * Parse access token request and extract the grant specific properties.
   *
   * If something goes wrong, such as the grant is not supported, missing parameters, etc,
   * it will throw `Oauth2ServerErrorResponseError` containing an error response object
   * that can be returned to the client.
   */
  public parseAccessTokenRequest(options: ParseAccessTokenRequestOptions) {
    return parseAccessTokenRequest(options)
  }

  public verifyPreAuthorizedCodeAccessTokenRequest(
    options: Omit<VerifyPreAuthorizedCodeAccessTokenRequestOptions, 'callbacks'>
  ) {
    return verifyPreAuthorizedCodeAccessTokenRequest({
      ...options,
      callbacks: this.options.callbacks,
    })
  }

  public verifyAuthorizationCodeAccessTokenRequest(
    options: Omit<VerifyAuthorizationCodeAccessTokenRequestOptions, 'callbacks'>
  ) {
    return verifyAuthorizationCodeAccessTokenRequest({
      ...options,
      callbacks: this.options.callbacks,
    })
  }

  /**
   * Create an access token response.
   *
   * The `sub` claim can be used to identify the resource owner is subsequent requests.
   * For pre-auth flow this can be the pre-authorized_code but there are no requirements
   * on the value.
   */
  public async createAccessTokenResponse(
    options: Pick<
      CreateAccessTokenOptions,
      | 'expiresInSeconds'
      | 'scope'
      | 'clientId'
      | 'audience'
      | 'signer'
      | 'dpopJwk'
      | 'authorizationServer'
      | 'now'
      | 'subject'
    > &
      Pick<CreateAccessTokenResponseOptions, 'cNonce' | 'cNonceExpiresIn'> & {
        additionalAccessTokenPayload?: CreateAccessTokenOptions['additionalPayload']
        additionalAccessTokenResponsePayload?: CreateAccessTokenResponseOptions['additionalPayload']
      }
  ) {
    const { jwt: accessToken } = await createAccessTokenJwt({
      audience: options.audience,
      authorizationServer: options.authorizationServer,
      callbacks: this.options.callbacks,
      expiresInSeconds: options.expiresInSeconds,
      subject: options.subject,
      scope: options.scope,
      clientId: options.clientId,
      signer: options.signer,
      dpopJwk: options.dpopJwk,
      now: options.now,
      additionalPayload: options.additionalAccessTokenPayload,
    })

    return createAccessTokenResponse({
      accessToken,
      callbacks: this.options.callbacks,
      expiresInSeconds: options.expiresInSeconds,
      tokenType: options.dpopJwk ? 'DPoP' : 'Bearer',
      cNonce: options.cNonce,
      cNonceExpiresIn: options.cNonceExpiresIn,
      additionalPayload: options.additionalAccessTokenResponsePayload,
    })
  }

  /**
   * Parse an authorization challenge request
   */
  public parseAuthorizationChallengeRequest(options: ParseAuthorizationChallengeRequestOptions) {
    return parseAuthorizationChallengeRequest(options)
  }

  public createAuthorizationChallengeResponse(options: CreateAuthorizationChallengeResponseOptions) {
    return createAuthorizationChallengeResponse(options)
  }

  /**
   * Create an authorization challenge error response indicating presentation of credenitals
   * using OpenID4VP is required before authorization can be granted.
   *
   * The `presentation` parameter should be an OpenID4VP authorization request url.
   * The `authSession` should be used to track the session
   */
  public createAuthorizationChallengePresentationErrorResponse(
    options: Pick<CreateAuthorizationChallengeErrorResponseOptions, 'errorDescription' | 'additionalPayload'> &
      Required<Pick<CreateAuthorizationChallengeErrorResponseOptions, 'authSession' | 'presentation'>>
  ) {
    return createAuthorizationChallengeErrorResponse({
      error: Oauth2ErrorCodes.InsufficientAuthorization,
      errorDescription: options.errorDescription,
      additionalPayload: options.additionalPayload,
      authSession: options.authSession,
      presentation: options.presentation,
    })
  }

  public createAuthorizationChallengeErrorResponse(options: CreateAuthorizationChallengeErrorResponseOptions) {
    return createAuthorizationChallengeErrorResponse(options)
  }

  public async verifyClientAttestation({
    authorizationServer,
    headers,
  }: { authorizationServer: string; headers: FetchHeaders }) {
    const { clientAttestationHeader, clientAttestationPopHeader } = extractClientAttestationJwtsFromHeaders(headers)

    const clientAttestation = await verifyClientAttestationJwt({
      callbacks: this.options.callbacks,
      clientAttestationJwt: clientAttestationHeader,
    })

    const clientAttestationPop = await verifyClientAttestationPopJwt({
      callbacks: this.options.callbacks,
      authorizationServer,
      clientAttestation,
      clientAttestationPopJwt: clientAttestationPopHeader,
    })

    return {
      clientAttestation,
      clientAttestationPop,
    }
  }
}
