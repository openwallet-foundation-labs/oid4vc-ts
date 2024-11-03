import type { CallbackContext } from '@animo-id/oauth2'
import { type CreateCredentialOfferOptions, createCredentialOffer } from './credential-offer/credential-offer'

export interface Oid4vciIssuerOptions {
  /**
   * Callbacks required for the oid4vc issuer
   */
  callbacks: CallbackContext
}

export class Oid4vciIssuer {
  public constructor(private options: Oid4vciIssuerOptions) {}

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
}
