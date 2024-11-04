import type { CallbackContext } from '@animo-id/oauth2'
import { parseWithErrorHandling } from '@animo-id/oid4vc-utils'
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

  public async verifyCredentialRequestJwtProof(
    options: Pick<VerifyCredentialRequestJwtProofOptions, 'clientId' | 'jwt' | 'now' | 'expectedNonce'> & {
      issuerMetadata: IssuerMetadataResult
    }
  ) {
    return await verifyCredentialRequestJwtProof({
      callbacks: this.options.callbacks,
      credentialIssuer: options.issuerMetadata.credentialIssuer.credential_issuer,
      expectedNonce: options.expectedNonce,
      jwt: options.jwt,
      clientId: options.clientId,
      now: options.now,
    })
  }

  public parseCredentialRequest(options: ParseCredentialRequestOptions): ParseCredentialRequestReturn {
    return parseCredentialRequest(options)
  }

  public createCredentialResponse(options: CreateCredentialResponseOptions) {
    return createCredentialResponse(options)
  }
}
