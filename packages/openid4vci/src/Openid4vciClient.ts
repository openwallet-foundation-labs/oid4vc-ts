import {
  authorizationCodeGrantIdentifier,
  type CallbackContext,
  type CreateAuthorizationRequestUrlOptions,
  createPkce,
  getAuthorizationServerMetadataFromList,
  Oauth2Client,
  Oauth2ClientAuthorizationChallengeError,
  Oauth2Error,
  Oauth2ErrorCodes,
  type ParseAuthorizationResponseOptions,
  parseAuthorizationResponseRedirectUrl,
  preAuthorizedCodeGrantIdentifier,
  type RequestDpopOptions,
  type RetrieveAuthorizationCodeAccessTokenOptions,
  type RetrievePreAuthorizedCodeAccessTokenOptions,
  type VerifyAuthorizationResponseOptions,
  verifyAuthorizationResponse,
} from '@openid4vc/oauth2'
import { objectToQueryParams } from '@openid4vc/utils'
import {
  AuthorizationFlow,
  type AuthorizationFlowReturn,
  type InitiateAuthorizationOptions,
} from './authorization-flow'
import {
  determineAuthorizationServerForCredentialOffer,
  resolveCredentialOffer,
} from './credential-offer/credential-offer'
import type { CredentialOfferObject } from './credential-offer/z-credential-offer'
import { getCredentialRequestFormatPayloadForCredentialConfigurationId } from './credential-request/format-payload'
import {
  type RetrieveCredentialsResponseNotOk,
  type RetrieveCredentialsResponseOk,
  type RetrieveCredentialsWithFormatOptions,
  type RetrieveDeferredCredentialsOptions,
  type RetrieveDeferredCredentialsResponseOk,
  retrieveCredentialsWithCredentialConfigurationId,
  retrieveCredentialsWithFormat,
  retrieveDeferredCredentials,
} from './credential-request/retrieve-credentials'
import { Openid4vciError } from './error/Openid4vciError'
import { Openid4vciRetrieveCredentialsError } from './error/Openid4vciRetrieveCredentialsError'
import { Openid4vciSendNotificationError } from './error/Openid4vciSendNotificationError'
import {
  type CreateCredentialRequestJwtProofOptions,
  createCredentialRequestJwtProof,
} from './formats/proof-type/jwt/jwt-proof-type'
import {
  type SendInteractiveAuthorizationRequestOptions,
  sendInteractiveAuthorizationRequest,
} from './interactive-authorization/send-interactive-authorization-request'
import { type IssuerMetadataResult, resolveIssuerMetadata } from './metadata/fetch-issuer-metadata'
import { type RequestNonceOptions, requestNonce } from './nonce/nonce-request'
import { type SendNotificationOptions, sendNotification } from './notification/notification'
import { Openid4vciVersion } from './version'

export interface Openid4vciClientOptions {
  /**
   * Callbacks required for the openid4vc client
   */
  callbacks: Omit<CallbackContext, 'verifyJwt' | 'decryptJwe' | 'encryptJwe'>
}

export class Openid4vciClient {
  private oauth2Client: Oauth2Client

  public constructor(private options: Openid4vciClientOptions) {
    this.oauth2Client = new Oauth2Client({
      callbacks: this.options.callbacks,
    })
  }

  /**
   * Resolve a credential offer into a credential offer object, handling both
   * 'credential_offer' and 'credential_offer_uri' params.
   */
  public async resolveCredentialOffer(credentialOffer: string): Promise<CredentialOfferObject> {
    return resolveCredentialOffer(credentialOffer, {
      fetch: this.options.callbacks.fetch,
    })
  }

  public async resolveIssuerMetadata(credentialIssuer: string): Promise<IssuerMetadataResult> {
    return resolveIssuerMetadata(credentialIssuer, {
      callbacks: this.options.callbacks,
    })
  }

  /**
   * Retrieve an authorization code for a legacy presentation during issuance session
   *
   * This can only be called if the initiateAuthorization returned {@link AuthorizationFlow.PresentationDuringIssuance}.
   *
   * This can only be called if an authorization challenge was performed before and returned a
   * `presentation` parameter along with an `auth_session`. If the presentation response included
   * an `presentation_during_issuance_session` parameter it MUST be included in this request as well.
   */
  public async retrieveAuthorizationCodeUsingPresentation(options: {
    /**
     * Auth session as returned by `{@link Openid4vciClient.initiateAuthorization}
     */
    authSession: string

    /**
     * Presentation during issuance session, obtained from the RP after submitting
     * openid4vp authorization response
     */
    presentationDuringIssuanceSession?: string

    credentialOffer: CredentialOfferObject
    issuerMetadata: IssuerMetadataResult

    dpop?: RequestDpopOptions
  }) {
    if (!options.credentialOffer.grants?.[authorizationCodeGrantIdentifier]) {
      throw new Oauth2Error(`Provided credential offer does not include the 'authorization_code' grant.`)
    }

    const authorizationCodeGrant = options.credentialOffer.grants[authorizationCodeGrantIdentifier]
    const authorizationServer = determineAuthorizationServerForCredentialOffer({
      issuerMetadata: options.issuerMetadata,
      grantAuthorizationServer: authorizationCodeGrant.authorization_server,
    })

    const authorizationServerMetadata = getAuthorizationServerMetadataFromList(
      options.issuerMetadata.authorizationServers,
      authorizationServer
    )

    const oauth2Client = new Oauth2Client({ callbacks: this.options.callbacks })
    const { authorizationChallengeResponse, dpop } = await oauth2Client.sendAuthorizationChallengeRequest({
      authorizationServerMetadata,
      authSession: options.authSession,
      presentationDuringIssuanceSession: options.presentationDuringIssuanceSession,
      dpop: options.dpop,
    })

    return { authorizationChallengeResponse, dpop }
  }

  /**
   * Retrieve authorization code using Interactive Authorization Endpoint after OpenID4VP presentation
   *
   * This method is used when the Interactive Authorization Endpoint requires an OpenID4VP presentation.
   * After completing the presentation, call this method with the auth_session and the openid4vp_response.
   *
   * @param options - Options including auth_session and openid4vp_response
   * @returns The authorization code
   */
  public async retrieveAuthorizationCodeUsingInteractiveAuthorization(options: {
    authSession: string

    openid4vpResponse?: string
    credentialOffer: CredentialOfferObject
    issuerMetadata: IssuerMetadataResult
    dpop?: RequestDpopOptions
  }) {
    const authorizationCodeGrant = options.credentialOffer.grants?.[authorizationCodeGrantIdentifier]
    if (!authorizationCodeGrant) {
      throw new Oauth2Error(`Provided credential offer does not include the 'authorization_code' grant.`)
    }

    const authorizationServer = determineAuthorizationServerForCredentialOffer({
      issuerMetadata: options.issuerMetadata,
      grantAuthorizationServer: authorizationCodeGrant.authorization_server,
    })

    const authorizationServerMetadata = getAuthorizationServerMetadataFromList(
      options.issuerMetadata.authorizationServers,
      authorizationServer
    )

    if (!authorizationServerMetadata.interactive_authorization_endpoint) {
      throw new Openid4vciError('Authorization server does not support interactive authorization endpoint')
    }

    const { interactiveAuthorizationResponse, dpop } = await this.sendInteractiveAuthorizationRequest({
      authorizationServerMetadata,
      request: {
        auth_session: options.authSession,
        openid4vp_response: options.openid4vpResponse,
      },
      dpop: options.dpop,
    })

    if (interactiveAuthorizationResponse.status !== 'ok') {
      throw new Openid4vciError(
        `Interactive authorization did not return status 'ok'. Received status '${interactiveAuthorizationResponse.status}'.`
      )
    }

    return {
      authorizationCode: interactiveAuthorizationResponse.code,
      dpop,
    }
  }

  /**
   * Initiates authorization for credential issuance. It handles the following cases (in order):
   * - Interactive Authorization Endpoint (OpenID4VCI 1.1) - preferred method
   * - Authorization Challenge (OAuth 2.0 First-Party Applications) - fallback
   * - Pushed Authorization Request
   * - Regular Authorization url
   *
   * The Interactive Authorization Endpoint can return:
   * - `status: 'require_interaction'` with type 'openid4vp_presentation' (requires OpenID4VP presentation)
   * - `status: 'require_interaction'` with type 'redirect_to_web' (requires browser redirect)
   *
   * For Authorization Challenge (legacy), an error with `insufficient_authorization` and `presentation`
   * field means the AS expects presentation of credentials before issuance. The value in `presentation`
   * should be treated as an OpenID4VP authorization request. Once submitted, the RP will respond with
   * a `presentation_during_issuance_session` parameter. Together with the `auth_session` you can
   * retrieve an authorization code using {@link retrieveAuthorizationCodeUsingPresentation}.
   */
  public async initiateAuthorization(options: InitiateAuthorizationOptions): Promise<AuthorizationFlowReturn> {
    if (!options.credentialOffer.grants?.[authorizationCodeGrantIdentifier]) {
      throw new Oauth2Error(`Provided credential offer does not include the 'authorization_code' grant.`)
    }

    const authorizationCodeGrant = options.credentialOffer.grants[authorizationCodeGrantIdentifier]
    const authorizationServer = determineAuthorizationServerForCredentialOffer({
      issuerMetadata: options.issuerMetadata,
      grantAuthorizationServer: authorizationCodeGrant.authorization_server,
    })

    const authorizationServerMetadata = getAuthorizationServerMetadataFromList(
      options.issuerMetadata.authorizationServers,
      authorizationServer
    )

    const oauth2Client = new Oauth2Client({ callbacks: this.options.callbacks })

    try {
      // Prefer Interactive Authorization Endpoint (IAE) - successor to authorization challenge
      if (authorizationServerMetadata.interactive_authorization_endpoint) {
        const pkce = authorizationServerMetadata.code_challenge_methods_supported
          ? await createPkce({
              allowedCodeChallengeMethods: authorizationServerMetadata.code_challenge_methods_supported,
              callbacks: this.options.callbacks,
              codeVerifier: options.pkceCodeVerifier,
            })
          : undefined

        const result = await this.sendInteractiveAuthorizationRequest({
          authorizationServerMetadata,
          request: {
            response_type: 'code',
            client_id: options.clientId,
            // For now we only support two hardcoded variants, future release can support
            // custom types so the flow is extensible.
            interaction_types_supported: ['redirect_to_web', 'openid4vp_presentation'].join(','),
            scope: options.scope,
            redirect_uri: options.redirectUri,
            resource: options.resource,
            state: options.state,
            code_challenge: pkce?.codeChallenge,
            code_challenge_method: pkce?.codeChallengeMethod,
            ...options.additionalRequestPayload,
          },
          dpop: options.dpop,
        })

        const response = result.interactiveAuthorizationResponse

        // Not supported at the moment, should not happen
        if (response.status === 'ok') {
          throw new Oauth2Error(
            'Received a successful authorization code response from interactive authorization endpoint without authorization'
          )
        }

        // If interaction is required (discriminated union provides type narrowing)
        if (response.status === 'require_interaction') {
          // Handle redirect_to_web interaction type
          if (response.type === 'redirect_to_web') {
            // Type is narrowed to InteractiveAuthorizationRedirectToWebResponse
            // request_uri is guaranteed to be present
            const authorizationRequestUrl = `${authorizationServerMetadata.authorization_endpoint}?${objectToQueryParams(
              {
                request_uri: response.request_uri,
                client_id: options.clientId,
              }
            ).toString()}`

            return {
              authorizationFlow: AuthorizationFlow.Oauth2Redirect,
              authorizationServer,
              dpop: result.dpop,

              authorizationRequestUrl,
              pkce,
            }
          }

          // Handle openid4vp_presentation interaction type
          if (response.type === 'openid4vp_presentation') {
            // Type is narrowed to InteractiveAuthorizationOpenid4vpPresentationResponse
            // openid4vp_request is guaranteed to be present
            return {
              authorizationFlow: AuthorizationFlow.InteractiveAuthorizationOpenid4vp,
              authorizationServer,
              dpop: result.dpop,

              openid4vpRequest: response.openid4vp_request,
              authSession: response.auth_session,
            }
          }

          // If require_interaction but no supported interaction type, fall back to normal flow
          // This can happen if a custom interaction type is used that we don't handle
        }
      }

      const result = await oauth2Client.initiateAuthorization({
        clientId: options.clientId,
        pkceCodeVerifier: options.pkceCodeVerifier,
        redirectUri: options.redirectUri,
        scope: options.scope,
        additionalRequestPayload: {
          ...options.additionalRequestPayload,
          issuer_state: options.credentialOffer?.grants?.authorization_code?.issuer_state,
        },
        dpop: options.dpop,
        resource: options.issuerMetadata.credentialIssuer.credential_issuer,
        authorizationServerMetadata,
      })

      return {
        ...result,
        authorizationFlow: AuthorizationFlow.Oauth2Redirect,
        authorizationServer: authorizationServerMetadata.issuer,
      }
    } catch (error) {
      // Handle Authorization Challenge presentation during issuance (legacy)
      if (
        error instanceof Oauth2ClientAuthorizationChallengeError &&
        error.errorResponse.error === Oauth2ErrorCodes.InsufficientAuthorization &&
        error.errorResponse.presentation
      ) {
        if (!error.errorResponse.auth_session) {
          throw new Openid4vciError(
            `Expected 'auth_session' to be defined with authorization challenge response error '${error.errorResponse.error}' and 'presentation' parameter`
          )
        }
        return {
          authorizationFlow: AuthorizationFlow.PresentationDuringIssuance,
          openid4vpRequestUrl: error.errorResponse.presentation,
          authSession: error.errorResponse.auth_session,
          authorizationServer: authorizationServerMetadata.issuer,
        }
      }

      throw error
    }
  }

  /**
   * Convenience method around {@link Oauth2Client.createAuthorizationRequestUrl}
   * but specifically focused on a credential offer
   */
  public async createAuthorizationRequestUrlFromOffer(
    options: Omit<CreateAuthorizationRequestUrlOptions, 'callbacks' | 'authorizationServerMetadata'> & {
      credentialOffer: CredentialOfferObject
      issuerMetadata: IssuerMetadataResult
    }
  ) {
    if (!options.credentialOffer.grants?.[authorizationCodeGrantIdentifier]) {
      throw new Oauth2Error(`Provided credential offer does not include the 'authorization_code' grant.`)
    }

    const authorizationCodeGrant = options.credentialOffer.grants[authorizationCodeGrantIdentifier]
    const authorizationServer = determineAuthorizationServerForCredentialOffer({
      issuerMetadata: options.issuerMetadata,
      grantAuthorizationServer: authorizationCodeGrant.authorization_server,
    })

    const authorizationServerMetadata = getAuthorizationServerMetadataFromList(
      options.issuerMetadata.authorizationServers,
      authorizationServer
    )

    const { authorizationRequestUrl, pkce, dpop } = await this.oauth2Client.createAuthorizationRequestUrl({
      authorizationServerMetadata,
      clientId: options.clientId,
      additionalRequestPayload: {
        ...options.additionalRequestPayload,
        issuer_state: options.credentialOffer?.grants?.authorization_code?.issuer_state,
      },
      resource: options.issuerMetadata.credentialIssuer.credential_issuer,
      redirectUri: options.redirectUri,
      scope: options.scope,
      pkceCodeVerifier: options.pkceCodeVerifier,
      dpop: options.dpop,
    })

    return {
      authorizationRequestUrl,
      pkce,
      dpop,
      authorizationServer: authorizationServerMetadata.issuer,
    }
  }

  /**
   * Convenience method around {@link Oauth2Client.retrievePreAuthorizedCodeAccessToken}
   * but specifically focused on a credential offer
   */
  public async retrievePreAuthorizedCodeAccessTokenFromOffer({
    credentialOffer,
    issuerMetadata,
    additionalRequestPayload,
    txCode,
    dpop,
  }: Omit<
    RetrievePreAuthorizedCodeAccessTokenOptions,
    'callbacks' | 'authorizationServerMetadata' | 'preAuthorizedCode' | 'resource'
  > & {
    credentialOffer: CredentialOfferObject
    issuerMetadata: IssuerMetadataResult
  }) {
    if (!credentialOffer.grants?.[preAuthorizedCodeGrantIdentifier]) {
      throw new Oauth2Error(`The credential offer does not contain the '${preAuthorizedCodeGrantIdentifier}' grant.`)
    }

    if (credentialOffer.grants[preAuthorizedCodeGrantIdentifier].tx_code && !txCode) {
      // TODO: we could further validate the tx_code, but not sure if that's needed?
      // the server will do that for us as well
      throw new Oauth2Error(
        `Retrieving access token requires a 'tx_code' in the request, but the 'txCode' parameter was not provided.`
      )
    }

    const preAuthorizedCode = credentialOffer.grants[preAuthorizedCodeGrantIdentifier]['pre-authorized_code']
    const authorizationServer = determineAuthorizationServerForCredentialOffer({
      grantAuthorizationServer: credentialOffer.grants[preAuthorizedCodeGrantIdentifier].authorization_server,
      issuerMetadata,
    })

    const authorizationServerMetadata = getAuthorizationServerMetadataFromList(
      issuerMetadata.authorizationServers,
      authorizationServer
    )

    const result = await this.oauth2Client.retrievePreAuthorizedCodeAccessToken({
      authorizationServerMetadata,
      preAuthorizedCode,
      txCode,
      resource: issuerMetadata.credentialIssuer.credential_issuer,
      additionalRequestPayload,
      dpop,
    })

    return {
      ...result,
      authorizationServer,
    }
  }

  /**
   * Parses the authorization (error) response redirect url, and verifies the
   * 'iss' value based on the authorization server metadata.
   *
   * If you need values from the authorization response (e.g. state) to retrieve the
   * authorization server metadata, you can manually import and call `parseAuthorizationResponseRedirectUrl` and
   * `verifyAuthorizationResponse`.
   */
  public parseAndVerifyAuthorizationResponseRedirectUrl(
    options: ParseAuthorizationResponseOptions & Omit<VerifyAuthorizationResponseOptions, 'authorizationResponse'>
  ) {
    const authorizationResponse = parseAuthorizationResponseRedirectUrl(options)

    verifyAuthorizationResponse({
      ...options,
      authorizationResponse,
    })

    return authorizationResponse
  }

  /**
   * Convenience method around {@link Oauth2Client.retrieveAuthorizationCodeAccessToken}
   * but specifically focused on a credential offer
   */
  public async retrieveAuthorizationCodeAccessTokenFromOffer({
    issuerMetadata,
    additionalRequestPayload,
    credentialOffer,
    authorizationCode,
    pkceCodeVerifier,
    redirectUri,
    dpop,
  }: Omit<RetrieveAuthorizationCodeAccessTokenOptions, 'authorizationServerMetadata' | 'callbacks'> & {
    credentialOffer: CredentialOfferObject
    issuerMetadata: IssuerMetadataResult
  }) {
    if (!credentialOffer.grants?.[authorizationCodeGrantIdentifier]) {
      throw new Oauth2Error(`The credential offer does not contain the '${authorizationCodeGrantIdentifier}' grant.`)
    }

    const authorizationServer = determineAuthorizationServerForCredentialOffer({
      grantAuthorizationServer: credentialOffer.grants[authorizationCodeGrantIdentifier].authorization_server,
      issuerMetadata,
    })

    const authorizationServerMetadata = getAuthorizationServerMetadataFromList(
      issuerMetadata.authorizationServers,
      authorizationServer
    )

    const result = await this.oauth2Client.retrieveAuthorizationCodeAccessToken({
      authorizationServerMetadata,
      authorizationCode,
      pkceCodeVerifier,
      additionalRequestPayload,
      dpop,
      redirectUri,
      resource: issuerMetadata.credentialIssuer.credential_issuer,
    })

    return {
      ...result,
      authorizationServer,
    }
  }

  /**
   * Request a nonce to be used in credential request proofs from the `nonce_endpoint`
   *
   * @throws Openid4vciError - if no `nonce_endpoint` is configured in the issuer metadata
   * @throws InvalidFetchResponseError - if the nonce endpoint did not return a successful response
   * @throws ValidationError - if validating the nonce response failed
   */
  public async requestNonce(options: Pick<RequestNonceOptions, 'issuerMetadata'>) {
    return requestNonce({
      ...options,
      fetch: this.options.callbacks.fetch,
    })
  }

  /**
   * Creates the jwt proof payload and header to be included in a credential request.
   */
  public async createCredentialRequestJwtProof(
    options: Pick<
      CreateCredentialRequestJwtProofOptions,
      'signer' | 'nonce' | 'issuedAt' | 'clientId' | 'keyAttestationJwt'
    > & {
      issuerMetadata: IssuerMetadataResult
      credentialConfigurationId: string
    }
  ) {
    const credentialConfiguration =
      options.issuerMetadata.credentialIssuer.credential_configurations_supported[options.credentialConfigurationId]
    if (!credentialConfiguration) {
      throw new Openid4vciError(
        `Credential configuration with '${options.credentialConfigurationId}' not found in 'credential_configurations_supported' from credential issuer '${options.issuerMetadata.credentialIssuer.credential_issuer}'`
      )
    }

    if (credentialConfiguration.proof_types_supported) {
      if (!credentialConfiguration.proof_types_supported.jwt) {
        throw new Openid4vciError(
          `Credential configuration with id '${options.credentialConfigurationId}' does not support the 'jwt' proof type.`
        )
      }

      if (
        !credentialConfiguration.proof_types_supported.jwt.proof_signing_alg_values_supported.includes(
          options.signer.alg
        )
      ) {
        throw new Openid4vciError(
          `Credential configuration with id '${options.credentialConfigurationId}' does not support the '${options.signer.alg}' alg for 'jwt' proof type.`
        )
      }

      // TODO: might be beneficial to also decode the key attestation and see if the required level is reached
      if (credentialConfiguration.proof_types_supported.jwt.key_attestations_required && !options.keyAttestationJwt) {
        throw new Openid4vciError(
          `Credential configuration with id '${options.credentialConfigurationId}' requires key attestations for 'jwt' proof type but no 'keyAttestationJwt' was provided`
        )
      }
    }

    const jwt = await createCredentialRequestJwtProof({
      credentialIssuer: options.issuerMetadata.credentialIssuer.credential_issuer,
      signer: options.signer,
      clientId: options.clientId,
      issuedAt: options.issuedAt,
      nonce: options.nonce,
      keyAttestationJwt: options.keyAttestationJwt,
      callbacks: this.options.callbacks,
    })

    return {
      jwt,
    }
  }

  /**
   * @throws Openid4vciRetrieveCredentialsError - if an unsuccessful response or the response couldn't be parsed as credential response
   * @throws ValidationError - if validation of the credential request failed
   * @throws Openid4vciError - if the `credentialConfigurationId` couldn't be found, or if the the format specific request couldn't be constructed
   */
  public async retrieveCredentials({
    issuerMetadata,
    proof,
    proofs,
    credentialConfigurationId,
    additionalRequestPayload,
    accessToken,
    dpop,
  }: Pick<
    RetrieveCredentialsWithFormatOptions,
    'accessToken' | 'additionalRequestPayload' | 'issuerMetadata' | 'proof' | 'proofs' | 'dpop'
  > & { credentialConfigurationId: string }) {
    let credentialResponse: RetrieveCredentialsResponseNotOk | RetrieveCredentialsResponseOk

    if (
      issuerMetadata.originalDraftVersion === Openid4vciVersion.Draft15 ||
      issuerMetadata.originalDraftVersion === Openid4vciVersion.V1
    ) {
      credentialResponse = await retrieveCredentialsWithCredentialConfigurationId({
        accessToken,
        credentialConfigurationId,
        issuerMetadata,
        additionalRequestPayload,
        proof,
        proofs,
        callbacks: this.options.callbacks,
        dpop,
      })
    } else {
      const formatPayload = getCredentialRequestFormatPayloadForCredentialConfigurationId({
        credentialConfigurationId,
        issuerMetadata,
      })

      credentialResponse = await retrieveCredentialsWithFormat({
        accessToken,
        formatPayload,
        issuerMetadata,
        additionalRequestPayload,
        proof,
        proofs,
        callbacks: this.options.callbacks,
        dpop,
      })
    }

    if (!credentialResponse.ok) {
      throw new Openid4vciRetrieveCredentialsError(
        `Error retrieving credentials from '${issuerMetadata.credentialIssuer.credential_issuer}'`,
        credentialResponse,
        await credentialResponse.response.clone().text()
      )
    }

    return credentialResponse
  }

  /**
   * @throws Openid4vciRetrieveCredentialsError - if an unsuccessful response or the response couldn't be parsed as credential response
   * @throws ValidationError - if validation of the credential request failed
   */
  public async retrieveDeferredCredentials(
    options: Pick<
      RetrieveDeferredCredentialsOptions,
      'issuerMetadata' | 'accessToken' | 'transactionId' | 'dpop' | 'additionalRequestPayload'
    >
  ): Promise<RetrieveDeferredCredentialsResponseOk> {
    const credentialResponse = await retrieveDeferredCredentials({
      ...options,
      callbacks: this.options.callbacks,
    })

    if (!credentialResponse.ok) {
      throw new Openid4vciRetrieveCredentialsError(
        `Error retrieving deferred credentials from '${options.issuerMetadata.credentialIssuer.credential_issuer}'`,
        credentialResponse,
        await credentialResponse.response.clone().text()
      )
    }

    return credentialResponse
  }

  /**
   * @throws Openid4vciSendNotificationError - if an unsuccessful response
   * @throws ValidationError - if validation of the notification request failed
   */
  public async sendNotification({
    issuerMetadata,
    notification,
    additionalRequestPayload,
    accessToken,
    dpop,
  }: Pick<
    SendNotificationOptions,
    'accessToken' | 'additionalRequestPayload' | 'issuerMetadata' | 'dpop' | 'notification'
  >) {
    const notificationResponse = await sendNotification({
      accessToken,
      issuerMetadata,
      additionalRequestPayload,
      callbacks: this.options.callbacks,
      dpop,
      notification,
    })

    if (!notificationResponse.ok) {
      throw new Openid4vciSendNotificationError(
        `Error sending notification to '${issuerMetadata.credentialIssuer.credential_issuer}'`,
        notificationResponse
      )
    }

    return notificationResponse
  }

  /**
   * Send an Interactive Authorization Request
   *
   * This method sends a request to the Interactive Authorization Endpoint.
   * Supports both initial requests and follow-up requests.
   *
   * @param options - Request options
   * @returns The interactive authorization response and updated DPoP config
   */
  public async sendInteractiveAuthorizationRequest(
    options: Omit<SendInteractiveAuthorizationRequestOptions, 'callbacks'>
  ) {
    return sendInteractiveAuthorizationRequest({
      ...options,
      callbacks: this.options.callbacks,
    })
  }
}

export { AuthorizationFlow }
