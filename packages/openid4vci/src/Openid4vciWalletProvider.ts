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

  public async createClientAttestationJwt(options: Omit<CreateClientAttestationJwtOptions, 'callbacks'>) {
    return await createClientAttestationJwt({
      callbacks: this.options.callbacks,
      ...options,
    })
  }

  public async createKeyAttestationJwt(options: Omit<CreateKeyAttestationJwtOptions, 'callbacks'>) {
    return await createKeyAttestationJwt({
      callbacks: this.options.callbacks,
      ...options,
    })
  }
}
