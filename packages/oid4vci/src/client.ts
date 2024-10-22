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
import type { HashCallback } from './callbacks'
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
import { type IssuerMetadataResult, resolveIssuerMetadata } from './metadata/fetch-issuer-metadata'
import type { Fetch } from './utils/valibot-fetcher'

export interface Oid4vciClientOptions {
  /**
   * Custom fetch implementation to use
   */
  fetch?: Fetch

  /**
   * Hash callback used for calculating the code verifier. Should be provided
   * to allow usage of the 'S256' code challeng method.
   */
  hashCallback?: HashCallback
}

export class Oid4vciClient {
  public constructor(private options?: Oid4vciClientOptions) {}

  /**
   * Resolve a credential offer into a credential offer object, handling both
   * 'credential_offer' and 'credential_offer_uri' params.
   */
  public async resolveCredentialOffer(credentialOffer: string): Promise<CredentialOfferObject> {
    return resolveCredentialOffer(credentialOffer, {
      fetch: this.options?.fetch,
    })
  }

  public async resolveIssuerMetadata(credentialIssuer: string): Promise<IssuerMetadataResult> {
    return resolveIssuerMetadata(credentialIssuer, {
      fetch: this.options?.fetch,
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
      fetch: this.options?.fetch,
      clientId: options.clientId,
      issuerMetadata: options.issuerMetadata,
      additionalRequestPayload: options.additionalRequestPayload,
      issuerState: options.credentialOffer?.grants?.authorization_code?.issuer_state,
      redirectUri: options.redirectUri,
      scope: options.scope,
      pkceCodeVerifier: options.pkceCodeVerifier,
      hashCallback: this.options?.hashCallback,
    })
  }

  public async retrievePreAuthorizedCodeAccessToken({
    credentialOffer,
    issuerMetadata,
    additionalRequestPayload,
    txCode,
  }: Pick<RetrievePreAuthorizedCodeAccessTokenOptions, 'txCode' | 'issuerMetadata' | 'additionalRequestPayload'> & {
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

    // TODO: it could be that authorization_server is not defined, but there are multiple authorization servers
    // we should validate that
    const authorizationServer =
      credentialOffer.grants[preAuthorizedCodeGrantIdentifier].authorization_server ??
      issuerMetadata.authorizationServers[0].issuer

    return {
      accessTokenResponse: await retrievePreAuthorizedCodeAccessToken({
        authorizationServer,
        issuerMetadata,
        preAuthorizedCode,
        txCode,
        additionalRequestPayload,
        fetch: this.options?.fetch,
      }),
      authorizationServer,
    }
  }

  public async retrieveAuthorizationCodeAccessToken({
    issuerMetadata,
    additionalRequestPayload,
    authorizationServer,
    authorizationCode,
    pkceCodeVerifier,
  }: Pick<
    RetrieveAuthorizationCodeAccessTokenOptions,
    'issuerMetadata' | 'additionalRequestPayload' | 'authorizationServer' | 'authorizationCode' | 'pkceCodeVerifier'
  >): Promise<{
    accessTokenResponse: AccessTokenResponse
    authorizationServer: string
  }> {
    return {
      accessTokenResponse: await retrieveAuthorizationCodeAccessToken({
        authorizationServer,
        issuerMetadata,
        authorizationCode,
        pkceCodeVerifier,
        additionalRequestPayload,
        fetch: this.options?.fetch,
      }),
      authorizationServer,
    }
  }

  /**
   * Creates the jwt proof payload and header to be included in a credential request.
   */
  public createCredentialRequestJwtProof(
    options: Pick<CreateCredentialRequestJwtProofOptions, 'alg' | 'signer' | 'nonce' | 'issuedAt' | 'clientId'> & {
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

      if (!credentialConfiguration.proof_types_supported.jwt.proof_signing_alg_values_supported.includes(options.alg)) {
        throw new Oid4vcError(
          `Credential configuration with id '${options.credentialConfigurationId}' does not support the '${options.alg}' alg for 'jwt' proof type.`
        )
      }
    }

    return createCredentialRequestJwtProof({
      alg: options.alg,
      credentialIssuer: options.issuerMetadata.credentialIssuer.credential_issuer,
      signer: options.signer,
      clientId: options.clientId,
      issuedAt: options.issuedAt,
      nonce: options.nonce,
    })
  }

  public async retrieveCredentials({
    issuerMetadata,
    proof,
    proofs,
    credentialConfigurationId,
    additionalRequestPayload,
    accessToken,
  }: Pick<
    RetrieveCredentialsWithFormatOptions,
    'accessToken' | 'additionalRequestPayload' | 'issuerMetadata' | 'proof' | 'proofs'
  > & { credentialConfigurationId: string }) {
    const formatPayload = getCredentialRequestFormatPayloadForCredentialConfigurationId({
      credentialConfigurationId,
      issuerMetadata,
    })

    const credentialResponse = await retrieveCredentialsWithFormat({
      accessToken,
      formatPayload,
      issuerMetadata,
      additionalRequestPayload,
      proof,
      proofs,
      fetch: this.options?.fetch,
    })

    return {
      credentialResponse,
    }
  }
}
