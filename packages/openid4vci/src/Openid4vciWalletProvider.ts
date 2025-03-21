import {
  type CallbackContext,
  type CreateClientAttestationJwtOptions,
  createClientAttestationJwt,
} from '@openid4vc/oauth2'
import { type CreateKeyAttestationJwtOptions, createKeyAttestationJwt } from './key-attestation/key-attestation'

export interface Openid4vciWalletProviderOptions {
  /**
   * Callbacks required for the openid4vc issuer
   */
  callbacks: Pick<CallbackContext, 'signJwt'>
}

export class Openid4vciWalletProvider {
  public constructor(private options: Openid4vciWalletProviderOptions) {}

  public async createWalletAttestationJwt(
    options: Omit<CreateClientAttestationJwtOptions, 'callbacks'> & { walletName?: string; walletLink?: string }
  ) {
    const additionalPayload = options.additionalPayload
      ? {
          wallet_name: options.walletName,
          wallet_link: options.walletLink,
          ...options.additionalPayload,
        }
      : {
          wallet_name: options.walletName,
          wallet_link: options.walletLink,
        }

    return await createClientAttestationJwt({
      ...options,
      callbacks: this.options.callbacks,
      additionalPayload,
    })
  }

  public async createKeyAttestationJwt(options: Omit<CreateKeyAttestationJwtOptions, 'callbacks'>) {
    return await createKeyAttestationJwt({
      callbacks: this.options.callbacks,
      ...options,
    })
  }
}
