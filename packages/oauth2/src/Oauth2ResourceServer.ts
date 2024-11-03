import { type VerifyResourceRequestOptions, verifyResourceRequest } from '.'
import type { CallbackContext } from './callbacks'

export interface Oauth2ResourceServerOptions {
  /**
   * Callbacks required for the oauth2 resource server
   */
  callbacks: Pick<CallbackContext, 'verifyJwt' | 'hash' | 'clientAuthentication' | 'fetch'>
}

export class Oauth2ResourceServer {
  public constructor(private options: Oauth2ResourceServerOptions) {}

  public async verifyResourceRequest(options: Omit<VerifyResourceRequestOptions, 'callbacks'>) {
    return verifyResourceRequest({
      callbacks: this.options.callbacks,
      ...options,
    })
  }
}
