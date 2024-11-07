import {
  type CallbackContext,
  Oauth2ErrorCodes,
  Oauth2JwtVerificationError,
  Oauth2ServerErrorResponseError,
} from '@animo-id/oauth2'
import { ValidationError, parseWithErrorHandling } from '@animo-id/oauth2-utils'
import { type CreateCredentialOfferOptions, createCredentialOffer } from './credential-offer/credential-offer'
import {
  type CreateCredentialResponseOptions,
  createCredentialResponse,
} from './credential-request/credential-response'
import {
  type ParseCredentialRequestOptions,
  type ParseCredentialRequestReturn,
  parseCredentialRequest,
} from './credential-request/parse-credential-request'
import { Oid4vciError } from './error/Oid4vciError'
import {
  type VerifyCredentialRequestJwtProofOptions,
  verifyCredentialRequestJwtProof,
} from './formats/proof-type/jwt/jwt-proof-type'
import { extractKnownCredentialConfigurationSupportedFormats } from './metadata/credential-issuer/credential-issuer-metadata'
import {
  type CredentialIssuerMetadata,
  vCredentialIssuerMetadata,
  vCredentialIssuerMetadataWithDraft11,
} from './metadata/credential-issuer/v-credential-issuer-metadata'
import type { IssuerMetadataResult } from './metadata/fetch-issuer-metadata'

export interface Oid4vciIssuerOptions {
  /**
   * Callbacks required for the oid4vc issuer
   */
  callbacks: CallbackContext
}

export class Oid4vciIssuer {
  public constructor(private options: Oid4vciIssuerOptions) {}

  public getCredentialIssuerMetadataDraft11(credentialIssuerMetadata: CredentialIssuerMetadata) {
    return parseWithErrorHandling(vCredentialIssuerMetadataWithDraft11, credentialIssuerMetadata)
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
      vCredentialIssuerMetadata,
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
        jwt: options.jwt,
        clientId: options.clientId,
        now: options.now,
      })
    } catch (error) {
      throw new Oauth2ServerErrorResponseError(
        {
          error: Oauth2ErrorCodes.InvalidProof,
          error_description:
            // TOOD: error should have a internalErrorMessage and a publicErrorMessage
            error instanceof Oauth2JwtVerificationError || error instanceof Oid4vciError
              ? error.message
              : 'Invalid proof',
        },
        'Error verifying credential request proof jwt',
        {
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
        'Error verifying credential request proof jwt',
        {
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
}
