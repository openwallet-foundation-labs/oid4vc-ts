import {
  type CallbackContext,
  Oauth2AuthorizationServer,
  Oauth2ErrorCodes,
  Oauth2JwtVerificationError,
  Oauth2ServerErrorResponseError,
} from '@openid4vc/oauth2'
import { parseWithErrorHandling, ValidationError } from '@openid4vc/utils'
import type { VerifyClientAttestationOptions } from '../../oauth2/src/client-attestation/client-attestation'
import { type CreateCredentialOfferOptions, createCredentialOffer } from './credential-offer/credential-offer'
import {
  type CreateCredentialResponseOptions,
  type CreateDeferredCredentialResponseOptions,
  createCredentialResponse,
  createDeferredCredentialResponse,
} from './credential-request/credential-response'
import {
  type ParseCredentialRequestOptions,
  type ParseCredentialRequestReturn,
  parseCredentialRequest,
} from './credential-request/parse-credential-request'
import {
  type ParseDeferredCredentialRequestOptions,
  type ParseDeferredCredentialRequestReturn,
  parseDeferredCredentialRequest,
} from './credential-request/parse-deferred-credential-request'
import { Openid4vciError } from './error/Openid4vciError'
import {
  type VerifyCredentialRequestAttestationProofOptions,
  verifyCredentialRequestAttestationProof,
} from './formats/proof-type/attestation/attestation-proof-type'
import {
  type VerifyCredentialRequestJwtProofOptions,
  verifyCredentialRequestJwtProof,
} from './formats/proof-type/jwt/jwt-proof-type'
import { extractKnownCredentialConfigurationSupportedFormats } from './metadata/credential-issuer/credential-issuer-metadata'
import {
  type CredentialIssuerMetadata,
  zCredentialIssuerMetadata,
  zCredentialIssuerMetadataWithDraft11,
} from './metadata/credential-issuer/z-credential-issuer-metadata'
import type { IssuerMetadataResult } from './metadata/fetch-issuer-metadata'
import { type CreateNonceResponseOptions, createNonceResponse } from './nonce/nonce-request'

export interface Openid4vciIssuerOptions {
  /**
   * Callbacks required for the openid4vc issuer
   */
  callbacks: Omit<CallbackContext, 'decryptJwe' | 'encryptJwe'>
}

export class Openid4vciIssuer {
  public constructor(private options: Openid4vciIssuerOptions) {}

  public getCredentialIssuerMetadataDraft11(credentialIssuerMetadata: CredentialIssuerMetadata) {
    return parseWithErrorHandling(zCredentialIssuerMetadataWithDraft11, credentialIssuerMetadata)
  }

  public getKnownCredentialConfigurationsSupported(credentialIssuerMetadata: CredentialIssuerMetadata) {
    return extractKnownCredentialConfigurationSupportedFormats(
      credentialIssuerMetadata.credential_configurations_supported
    )
  }

  /**
   * Create issuer metadata and validates the structure is correct
   */
  public createCredentialIssuerMetadata(credentialIssuerMetadata: CredentialIssuerMetadata): CredentialIssuerMetadata {
    return parseWithErrorHandling(
      zCredentialIssuerMetadata,
      credentialIssuerMetadata,
      'Error validating credential issuer metadata'
    )
  }

  public async createCredentialOffer(
    options: Pick<
      CreateCredentialOfferOptions,
      | 'issuerMetadata'
      | 'additionalPayload'
      | 'grants'
      | 'credentialOfferUri'
      | 'credentialOfferScheme'
      | 'credentialConfigurationIds'
    >
  ) {
    return createCredentialOffer({
      callbacks: this.options.callbacks,
      credentialConfigurationIds: options.credentialConfigurationIds,
      grants: options.grants,
      issuerMetadata: options.issuerMetadata,
      additionalPayload: options.additionalPayload,
      credentialOfferScheme: options.credentialOfferScheme,
      credentialOfferUri: options.credentialOfferUri,
    })
  }

  /**
   * @throws Oauth2ServerErrorResponseError - if verification of the jwt failed. You can extract
   *  the credential error response from this.
   */
  public async verifyCredentialRequestJwtProof(
    options: Pick<
      VerifyCredentialRequestJwtProofOptions,
      'clientId' | 'jwt' | 'now' | 'expectedNonce' | 'nonceExpiresAt'
    > & {
      issuerMetadata: IssuerMetadataResult
    }
  ) {
    try {
      return await verifyCredentialRequestJwtProof({
        callbacks: this.options.callbacks,
        credentialIssuer: options.issuerMetadata.credentialIssuer.credential_issuer,
        expectedNonce: options.expectedNonce,
        nonceExpiresAt: options.nonceExpiresAt,
        jwt: options.jwt,
        clientId: options.clientId,
        now: options.now,
      })
    } catch (error) {
      throw new Oauth2ServerErrorResponseError(
        {
          error: Oauth2ErrorCodes.InvalidProof,
          error_description:
            // TODO: error should have a internalErrorMessage and a publicErrorMessage
            error instanceof Oauth2JwtVerificationError || error instanceof Openid4vciError
              ? error.message
              : 'Invalid proof',
        },

        {
          internalMessage: 'Error verifying credential request proof jwt',
          cause: error,
        }
      )
    }
  }

  /**
   * @throws Oauth2ServerErrorResponseError - if verification of the key attestation failed. You can extract
   *  the credential error response from this.
   */
  public async verifyCredentialRequestAttestationProof(
    options: Pick<
      VerifyCredentialRequestAttestationProofOptions,
      'keyAttestationJwt' | 'expectedNonce' | 'nonceExpiresAt' | 'now'
    > & {
      issuerMetadata: IssuerMetadataResult
    }
  ) {
    try {
      return await verifyCredentialRequestAttestationProof({
        callbacks: this.options.callbacks,
        expectedNonce: options.expectedNonce,
        keyAttestationJwt: options.keyAttestationJwt,
        nonceExpiresAt: options.nonceExpiresAt,
        now: options.now,
      })
    } catch (error) {
      throw new Oauth2ServerErrorResponseError(
        {
          error: Oauth2ErrorCodes.InvalidProof,
          error_description:
            // TODO: error should have a internalErrorMessage and a publicErrorMessage
            error instanceof Oauth2JwtVerificationError || error instanceof Openid4vciError
              ? error.message
              : 'Invalid proof',
        },

        {
          internalMessage: 'Error verifying credential request proof attestation',
          cause: error,
        }
      )
    }
  }

  /**
   * @throws Oauth2ServerErrorResponseError - when validation of the credential request fails
   *  You can extract the credential error response from this.
   */
  public parseCredentialRequest(options: ParseCredentialRequestOptions): ParseCredentialRequestReturn {
    try {
      // TODO: method should include reason for parsing - (e.g. unsupported format etc..)
      return parseCredentialRequest(options)
    } catch (error) {
      throw new Oauth2ServerErrorResponseError(
        {
          error: Oauth2ErrorCodes.InvalidCredentialRequest,
          error_description:
            // TODO: error should have a internalErrorMessage and a publicErrorMessage
            error instanceof ValidationError ? error.message : 'Invalid request',
        },
        {
          internalMessage: 'Error verifying credential request proof jwt',
          cause: error,
        }
      )
    }

    // TODO: might be nice to add some extra validation params here so it's
    // easy for an issuer to verify whether the request matches with the configuration
    // e.g. alg of holder binding, key_attestations_required, proof_types_supported,
    // request matches offer, etc..
  }

  /**
   * @throws Oauth2ServerErrorResponseError - when validation of the deferred credential request fails
   */
  public parseDeferredCredentialRequest(
    options: ParseDeferredCredentialRequestOptions
  ): ParseDeferredCredentialRequestReturn {
    try {
      return parseDeferredCredentialRequest(options)
    } catch (error) {
      throw new Oauth2ServerErrorResponseError(
        {
          error: Oauth2ErrorCodes.InvalidCredentialRequest,
          error_description: error instanceof ValidationError ? error.message : 'Invalid request',
        },
        {
          internalMessage: 'Error parsing deferred credential request',
          cause: error,
        }
      )
    }
  }

  /**
   * @throws ValidationError - when validation of the credential response fails
   */
  public createCredentialResponse(options: CreateCredentialResponseOptions) {
    return createCredentialResponse(options)
  }

  /**
   * @throws ValidationError - when validation of the credential response fails
   */
  public createDeferredCredentialResponse(options: CreateDeferredCredentialResponseOptions) {
    return createDeferredCredentialResponse(options)
  }

  /**
   * @throws ValidationError - when validation of the nonce response fails
   */
  public createNonceResponse(options: CreateNonceResponseOptions) {
    return createNonceResponse(options)
  }

  public async verifyWalletAttestation(options: Omit<VerifyClientAttestationOptions, 'callbacks'>) {
    return new Oauth2AuthorizationServer({
      callbacks: this.options.callbacks,
    }).verifyClientAttestation(options)
  }
}
