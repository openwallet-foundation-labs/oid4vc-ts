import {
  type RetrieveAuthorizationCodeAccessTokenOptions,
  type RetrievePreAuthorizedCodeAccessTokenOptions,
  retrieveAuthorizationCodeAccessToken,
  retrievePreAuthorizedCodeAccessToken,
} from './authorization/access-token/access-token'
import type { AccessTokenResponse } from './authorization/access-token/v-access-token'
import {
  type CreateAuthorizationRequestUrlOptions,
  createAuthorizationRequestUrl,
} from './authorization/authorization-request/authorization-request'
import type { CallbackContext } from './callbacks'
import { resolveCredentialOffer } from './credential-offer/credential-offer'
import { type CredentialOfferObject, preAuthorizedCodeGrantIdentifier } from './credential-offer/v-credential-offer'
import {
  type RetrieveCredentialsWithFormatOptions,
  retrieveCredentialsWithFormat,
} from './credential-request/credential-request'
import { getCredentialRequestFormatPayloadForCredentialConfigurationId } from './credential-request/format-payload'
import { Oid4vcError } from './error/Oid4vcError'
import {
  type CreateCredentialRequestJwtProofOptions,
  createCredentialRequestJwtProof,
} from './formats/proof-type/jwt/jwt-proof-type'
import { getAuthorizationServerMetadataFromList } from './metadata/authorization-server/authorization-server-metadata'
import { type IssuerMetadataResult, resolveIssuerMetadata } from './metadata/fetch-issuer-metadata'

export interface Oid4vciClientOptions {
  /**
   * Callbacks required for the oid4vc client
   */
  callbacks: Omit<CallbackContext, 'verifyJwt'>
}

export class Oid4vciClient {
  public constructor(private options: Oid4vciClientOptions) {}

  public async isDpopSupported(options: { authorizationServer: string; issuerMetadata: IssuerMetadataResult }) {
    const authorizationServerMetadata = getAuthorizationServerMetadataFromList(
      options.issuerMetadata.authorizationServers,
      options.authorizationServer
    )

    if (
      !authorizationServerMetadata.dpop_signing_alg_values_supported ||
      authorizationServerMetadata.dpop_signing_alg_values_supported.length === 0
    ) {
      return {
        supported: false,
      } as const
    }

    return {
      supported: true,
      dpopSigningAlgValuesSupported: authorizationServerMetadata.dpop_signing_alg_values_supported,
    } as const
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
      fetch: this.options.callbacks.fetch,
    })
  }

  public async createAuthorizationRequestUrl(
    options: Pick<
      CreateAuthorizationRequestUrlOptions,
      | 'additionalRequestPayload'
      | 'authorizationServer'
      | 'clientId'
      | 'issuerMetadata'
      | 'redirectUri'
      | 'scope'
      | 'pkceCodeVerifier'
    > & { credentialOffer?: CredentialOfferObject }
  ) {
    if (options.credentialOffer) {
      if (!options.credentialOffer.grants?.authorization_code) {
        throw new Oid4vcError(`Provided credential offer does not include the 'authorization_code' grant.`)
      }

      const authorizationCodeGrant = options.credentialOffer.grants.authorization_code
      if (
        authorizationCodeGrant.authorization_server &&
        authorizationCodeGrant.authorization_server !== options.authorizationServer
      ) {
        throw new Oid4vcError(
          `Provided 'authorizationServer' does not match with the 'authorization_server' from the 'authorization_code' grant in the credential offer`
        )
      }
    }

    return createAuthorizationRequestUrl({
      authorizationServer: options.authorizationServer,
      clientId: options.clientId,
      issuerMetadata: options.issuerMetadata,
      additionalRequestPayload: options.additionalRequestPayload,
      issuerState: options.credentialOffer?.grants?.authorization_code?.issuer_state,
      redirectUri: options.redirectUri,
      scope: options.scope,
      callbacks: this.options.callbacks,
      pkceCodeVerifier: options.pkceCodeVerifier,
    })
  }

  public async retrievePreAuthorizedCodeAccessToken({
    credentialOffer,
    issuerMetadata,
    additionalRequestPayload,
    txCode,
    dpop,
  }: Pick<
    RetrievePreAuthorizedCodeAccessTokenOptions,
    'txCode' | 'issuerMetadata' | 'additionalRequestPayload' | 'dpop'
  > & {
    credentialOffer: CredentialOfferObject
  }): Promise<{
    accessTokenResponse: AccessTokenResponse
    authorizationServer: string
  }> {
    if (!credentialOffer.grants?.[preAuthorizedCodeGrantIdentifier]) {
      throw new Oid4vcError(`The credential offer does not contain the '${preAuthorizedCodeGrantIdentifier}' grant.`)
    }

    if (credentialOffer.grants[preAuthorizedCodeGrantIdentifier].tx_code && !txCode) {
      // TODO: we could further validate the tx_code, but not sure if that's needed?
      // the server will do that for us as well
      throw new Oid4vcError(
        `Retrieving access token requires a 'tx_code' in the request, but the 'txCode' parameter was not provided.`
      )
    }

    const preAuthorizedCode = credentialOffer.grants[preAuthorizedCodeGrantIdentifier]['pre-authorized_code']

    let authorizationServer = credentialOffer.grants[preAuthorizedCodeGrantIdentifier].authorization_server
    if (!authorizationServer) {
      authorizationServer = issuerMetadata.authorizationServers[0].issuer
      if (issuerMetadata.authorizationServers.length > 1) {
        throw new Oid4vcError(
          `Credential issuer '${issuerMetadata.credentialIssuer.credential_issuer}' has multiple authorization servers configured, but the credential offer does not specify the 'authorization_server' to use in the '${preAuthorizedCodeGrantIdentifier}' grant.`
        )
      }
    }

    const result = await retrievePreAuthorizedCodeAccessToken({
      authorizationServer,
      issuerMetadata,
      preAuthorizedCode,
      txCode,
      additionalRequestPayload,
      callbacks: this.options.callbacks,
      dpop,
    })

    return {
      ...result,
      authorizationServer,
    }
  }

  public async retrieveAuthorizationCodeAccessToken({
    issuerMetadata,
    additionalRequestPayload,
    authorizationServer,
    authorizationCode,
    pkceCodeVerifier,
    redirectUri,
    dpop,
  }: Pick<
    RetrieveAuthorizationCodeAccessTokenOptions,
    | 'issuerMetadata'
    | 'additionalRequestPayload'
    | 'authorizationServer'
    | 'authorizationCode'
    | 'pkceCodeVerifier'
    | 'dpop'
    | 'redirectUri'
  >) {
    const result = await retrieveAuthorizationCodeAccessToken({
      authorizationServer,
      issuerMetadata,
      authorizationCode,
      pkceCodeVerifier,
      additionalRequestPayload,
      callbacks: this.options.callbacks,
      dpop,
      redirectUri,
    })

    return {
      ...result,
      authorizationServer,
    }
  }

  /**
   * Creates the jwt proof payload and header to be included in a credential request.
   */
  public async createCredentialRequestJwtProof(
    options: Pick<CreateCredentialRequestJwtProofOptions, 'signer' | 'nonce' | 'issuedAt' | 'clientId'> & {
      issuerMetadata: IssuerMetadataResult
      credentialConfigurationId: string
    }
  ) {
    const credentialConfiguration =
      options.issuerMetadata.credentialIssuer.credential_configurations_supported[options.credentialConfigurationId]
    if (!credentialConfiguration) {
      throw new Oid4vcError(
        `Credential configuration with '${options.credentialConfigurationId}' not found in 'credential_configurations_supported' from credential issuer '${options.issuerMetadata.credentialIssuer.credential_issuer}'`
      )
    }

    if (credentialConfiguration.proof_types_supported) {
      if (!credentialConfiguration.proof_types_supported.jwt) {
        throw new Oid4vcError(
          `Credential configuration with id '${options.credentialConfigurationId}' does not support the 'jwt' proof type.`
        )
      }

      if (
        !credentialConfiguration.proof_types_supported.jwt.proof_signing_alg_values_supported.includes(
          options.signer.alg
        )
      ) {
        throw new Oid4vcError(
          `Credential configuration with id '${options.credentialConfigurationId}' does not support the '${options.signer.alg}' alg for 'jwt' proof type.`
        )
      }
    }

    const jwtInput = createCredentialRequestJwtProof({
      credentialIssuer: options.issuerMetadata.credentialIssuer.credential_issuer,
      signer: options.signer,
      clientId: options.clientId,
      issuedAt: options.issuedAt,
      nonce: options.nonce,
    })

    const jwt = await this.options.callbacks.signJwt(options.signer, jwtInput)
    return {
      jwt,
    }
  }

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
    const formatPayload = getCredentialRequestFormatPayloadForCredentialConfigurationId({
      credentialConfigurationId,
      issuerMetadata,
    })

    return await retrieveCredentialsWithFormat({
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
}
