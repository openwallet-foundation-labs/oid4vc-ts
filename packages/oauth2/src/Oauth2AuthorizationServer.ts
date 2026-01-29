import { encodeToBase64Url, parseWithErrorHandling } from '@openid4vc/utils'
import { type CreateAccessTokenOptions, createAccessTokenJwt } from './access-token/create-access-token'
import {
  type CreateAccessTokenResponseOptions,
  createAccessTokenResponse,
} from './access-token/create-access-token-response'
import { type ParseAccessTokenRequestOptions, parseAccessTokenRequest } from './access-token/parse-access-token-request'
import {
  type VerifyAuthorizationCodeAccessTokenRequestOptions,
  type VerifyPreAuthorizedCodeAccessTokenRequestOptions,
  type VerifyRefreshTokenAccessTokenRequestOptions,
  verifyAuthorizationCodeAccessTokenRequest,
  verifyPreAuthorizedCodeAccessTokenRequest,
  verifyRefreshTokenAccessTokenRequest,
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
import {
  type VerifyAuthorizationChallengeRequestOptions,
  verifyAuthorizationChallengeRequest,
} from './authorization-challenge/verify-authorization-challenge-request'
import {
  type CreatePushedAuthorizationErrorResponseOptions,
  type CreatePushedAuthorizationResponseOptions,
  createPushedAuthorizationErrorResponse,
  createPushedAuthorizationResponse,
} from './authorization-request/create-pushed-authorization-response'
import {
  type ParsePushedAuthorizationRequestOptions,
  parsePushedAuthorizationRequest,
} from './authorization-request/parse-pushed-authorization-request'
import {
  type VerifyPushedAuthorizationRequestOptions,
  verifyPushedAuthorizationRequest,
} from './authorization-request/verify-pushed-authorization-request'
import type { CallbackContext } from './callbacks'
import { type VerifyClientAttestationOptions, verifyClientAttestation } from './client-attestation/client-attestation'
import { Oauth2ErrorCodes } from './common/z-oauth2-error'
import { type VerifyDpopJwtOptions, verifyDpopJwt } from './dpop/dpop'
import {
  type CreateInteractiveAuthorizationCodeResponseOptions,
  type CreateInteractiveAuthorizationErrorResponseOptions,
  type CreateInteractiveAuthorizationOpenid4vpInteractionOptions,
  type CreateInteractiveAuthorizationRedirectToWebInteractionOptions,
  createInteractiveAuthorizationCodeResponse,
  createInteractiveAuthorizationErrorResponse,
  createInteractiveAuthorizationOpenid4vpInteraction,
  createInteractiveAuthorizationRedirectToWebInteraction,
} from './interactive-authorization/create-interactive-authorization-response'
import {
  type ParseInteractiveAuthorizationRequestOptions,
  parseInteractiveAuthorizationRequest,
} from './interactive-authorization/parse-interactive-authorization-request'
import {
  type VerifyInteractiveAuthorizationRequestOptions,
  verifyInteractiveAuthorizationRequest,
} from './interactive-authorization/verify-interactive-authorization-request'
import {
  type AuthorizationServerMetadata,
  zAuthorizationServerMetadata,
} from './metadata/authorization-server/z-authorization-server-metadata'

export interface Oauth2AuthorizationServerOptions {
  /**
   * Callbacks required for the oauth2 authorization server
   */
  callbacks: Omit<CallbackContext, 'decryptJwe' | 'encryptJwe'>
}

export class Oauth2AuthorizationServer {
  public constructor(private options: Oauth2AuthorizationServerOptions) {}

  public createAuthorizationServerMetadata(authorizationServerMetadata: AuthorizationServerMetadata) {
    return parseWithErrorHandling(
      zAuthorizationServerMetadata,
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

  public verifyRefreshTokenAccessTokenRequest(options: Omit<VerifyRefreshTokenAccessTokenRequestOptions, 'callbacks'>) {
    return verifyRefreshTokenAccessTokenRequest({
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
   *
   * To generate a refresh token, set the `refreshToken` option to `true`. You can
   * also provide a custom refresh token string.
   */
  public async createAccessTokenResponse(
    options: Pick<
      CreateAccessTokenOptions,
      | 'expiresInSeconds'
      | 'scope'
      | 'clientId'
      | 'audience'
      | 'signer'
      | 'dpop'
      | 'authorizationServer'
      | 'now'
      | 'subject'
    > &
      Pick<CreateAccessTokenResponseOptions, 'cNonce' | 'cNonceExpiresIn'> & {
        additionalAccessTokenPayload?: CreateAccessTokenOptions['additionalPayload']
        additionalAccessTokenResponsePayload?: CreateAccessTokenResponseOptions['additionalPayload']
        refreshToken?: boolean | string
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
      dpop: options.dpop,
      now: options.now,
      additionalPayload: options.additionalAccessTokenPayload,
    })

    return createAccessTokenResponse({
      accessToken,
      refreshToken:
        typeof options.refreshToken === 'string'
          ? options.refreshToken
          : options.refreshToken
            ? encodeToBase64Url(await this.options.callbacks.generateRandom(32))
            : undefined,
      callbacks: this.options.callbacks,
      expiresInSeconds: options.expiresInSeconds,
      tokenType: options.dpop ? 'DPoP' : 'Bearer',
      cNonce: options.cNonce,
      cNonceExpiresIn: options.cNonceExpiresIn,
      additionalPayload: options.additionalAccessTokenResponsePayload,
    })
  }

  /**
   * Parse a pushed authorization request
   */
  public async parsePushedAuthorizationRequest(options: Omit<ParsePushedAuthorizationRequestOptions, 'callbacks'>) {
    return await parsePushedAuthorizationRequest({
      ...options,
      callbacks: this.options.callbacks,
    })
  }

  /**
   * Verify pushed authorization request.
   *
   * Make sure to provide the `authorizationRequestJwt` if this was returned in the `parsePushedAuthorizationRequest`
   */
  public verifyPushedAuthorizationRequest(options: Omit<VerifyPushedAuthorizationRequestOptions, 'callbacks'>) {
    return verifyPushedAuthorizationRequest({
      ...options,
      callbacks: this.options.callbacks,
    })
  }

  public createPushedAuthorizationResponse(options: CreatePushedAuthorizationResponseOptions) {
    return createPushedAuthorizationResponse(options)
  }

  public createPushedAuthorizationErrorResponse(options: CreatePushedAuthorizationErrorResponseOptions) {
    return createPushedAuthorizationErrorResponse(options)
  }

  /**
   * Parse an authorization challenge request
   */
  public parseAuthorizationChallengeRequest(options: ParseAuthorizationChallengeRequestOptions) {
    return parseAuthorizationChallengeRequest(options)
  }

  public verifyAuthorizationChallengeRequest(options: Omit<VerifyAuthorizationChallengeRequestOptions, 'callbacks'>) {
    return verifyAuthorizationChallengeRequest({
      ...options,
      callbacks: this.options.callbacks,
    })
  }

  public createAuthorizationChallengeResponse(options: CreateAuthorizationChallengeResponseOptions) {
    return createAuthorizationChallengeResponse(options)
  }

  /**
   * Create an authorization challenge error response indicating presentation of credentials
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

  /**
   * Parse an interactive authorization request
   *
   * Supports both initial and follow-up requests
   */
  public parseInteractiveAuthorizationRequest(options: ParseInteractiveAuthorizationRequestOptions) {
    return parseInteractiveAuthorizationRequest(options)
  }

  /**
   * Verify an interactive authorization request
   *
   * Verifies client attestation, DPoP, and authorization parameters
   */
  public verifyInteractiveAuthorizationRequest(
    options: Omit<VerifyInteractiveAuthorizationRequestOptions, 'callbacks'>
  ) {
    return verifyInteractiveAuthorizationRequest({
      ...options,
      callbacks: this.options.callbacks,
    })
  }

  /**
   * Create an interactive authorization code response
   *
   * Indicates successful completion of the authorization process
   */
  public createInteractiveAuthorizationCodeResponse(options: CreateInteractiveAuthorizationCodeResponseOptions) {
    return createInteractiveAuthorizationCodeResponse(options)
  }

  /**
   * Create an interactive authorization response requesting an OpenID4VP presentation
   *
   * The wallet must present credentials via OpenID4VP before authorization can be granted
   */
  public createInteractiveAuthorizationOpenid4vpInteraction(
    options: CreateInteractiveAuthorizationOpenid4vpInteractionOptions
  ) {
    return createInteractiveAuthorizationOpenid4vpInteraction(options)
  }

  /**
   * Create an interactive authorization response requesting a redirect to web
   *
   * The authorization process must continue via interactions with the user in a web browser
   */
  public createInteractiveAuthorizationRedirectToWebInteraction(
    options: CreateInteractiveAuthorizationRedirectToWebInteractionOptions
  ) {
    return createInteractiveAuthorizationRedirectToWebInteraction(options)
  }

  /**
   * Create an interactive authorization error response
   */
  public createInteractiveAuthorizationErrorResponse(options: CreateInteractiveAuthorizationErrorResponseOptions) {
    return createInteractiveAuthorizationErrorResponse(options)
  }

  public async verifyDpopJwt(options: Omit<VerifyDpopJwtOptions, 'callbacks'>) {
    return verifyDpopJwt({
      ...options,
      callbacks: this.options.callbacks,
    })
  }

  public async verifyClientAttestation(options: Omit<VerifyClientAttestationOptions, 'callbacks'>) {
    return verifyClientAttestation({
      ...options,
      callbacks: this.options.callbacks,
    })
  }
}
