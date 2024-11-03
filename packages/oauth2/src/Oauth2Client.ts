import {
  type RetrieveAuthorizationCodeAccessTokenOptions,
  type RetrievePreAuthorizedCodeAccessTokenOptions,
  retrieveAuthorizationCodeAccessToken,
  retrievePreAuthorizedCodeAccessToken,
} from './access-token/retrieve-access-token'
import {
  type CreateAuthorizationRequestUrlOptions,
  createAuthorizationRequestUrl,
} from './authorization-request/create-authorization-request'
import type { CallbackContext } from './callbacks'
import { fetchAuthorizationServerMetadata } from './metadata/authorization-server/authorization-server-metadata'
import type { AuthorizationServerMetadata } from './metadata/authorization-server/v-authorization-server-metadata'

export interface Oauth2ClientOptions {
  /**
   * Callbacks required for the oauth2 client
   */
  callbacks: Omit<CallbackContext, 'verifyJwt'>
}

export class Oauth2Client {
  public constructor(private options: Oauth2ClientOptions) {}

  public isDpopSupported(options: { authorizationServerMetadata: AuthorizationServerMetadata }) {
    if (
      !options.authorizationServerMetadata.dpop_signing_alg_values_supported ||
      options.authorizationServerMetadata.dpop_signing_alg_values_supported.length === 0
    ) {
      return {
        supported: false,
      } as const
    }

    return {
      supported: true,
      dpopSigningAlgValuesSupported: options.authorizationServerMetadata.dpop_signing_alg_values_supported,
    } as const
  }

  public async fetchAuthorizationServerMetadata(issuer: string) {
    return fetchAuthorizationServerMetadata(issuer, this.options.callbacks.fetch)
  }

  public async createAuthorizationRequestUrl(options: Omit<CreateAuthorizationRequestUrlOptions, 'callbacks'>) {
    return createAuthorizationRequestUrl({
      authorizationServerMetadata: options.authorizationServerMetadata,
      clientId: options.clientId,
      additionalRequestPayload: options.additionalRequestPayload,
      redirectUri: options.redirectUri,
      scope: options.scope,
      callbacks: this.options.callbacks,
      pkceCodeVerifier: options.pkceCodeVerifier,
    })
  }

  public async retrievePreAuthorizedCodeAccessToken({
    authorizationServerMetadata,
    preAuthorizedCode,
    additionalRequestPayload,
    txCode,
    dpop,
  }: Omit<RetrievePreAuthorizedCodeAccessTokenOptions, 'callbacks'>) {
    const result = await retrievePreAuthorizedCodeAccessToken({
      authorizationServerMetadata,
      preAuthorizedCode,
      txCode,
      additionalRequestPayload: {
        ...additionalRequestPayload,
        tx_code: txCode,
      },
      callbacks: this.options.callbacks,
      dpop,
    })

    return result
  }

  public async retrieveAuthorizationCodeAccessToken({
    authorizationServerMetadata,
    additionalRequestPayload,
    authorizationCode,
    pkceCodeVerifier,
    redirectUri,
    dpop,
  }: Omit<RetrieveAuthorizationCodeAccessTokenOptions, 'callbacks'>) {
    const result = await retrieveAuthorizationCodeAccessToken({
      authorizationServerMetadata,
      authorizationCode,
      pkceCodeVerifier,
      additionalRequestPayload,
      callbacks: this.options.callbacks,
      dpop,
      redirectUri,
    })

    return result
  }
}
