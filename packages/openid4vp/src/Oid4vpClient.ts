import type { CallbackContext } from '@openid4vc/oauth2'
import {} from './authorization-request/create-authorization-request'
import { parseOpenid4vpAuthorizationRequestPayload } from './authorization-request/parse-authorization-request-params'
import type { ParseOpenid4vpAuthRequestPayloadOptions } from './authorization-request/parse-authorization-request-params'
import {
  type ResolveOpenid4vpAuthorizationRequestOptions,
  resolveOpenid4vpAuthorizationRequest,
} from './authorization-request/resolve-authorization-request'
import {
  type CreateOpenid4vpAuthorizationResponseOptions,
  createOpenid4vpAuthorizationResponse,
} from './authorization-response/create-authorization-response'
import {
  type SubmitOpenid4vpAuthorizationResponseOptions,
  submitOpenid4vpAuthorizationResponse,
} from './authorization-response/submit-authorization-response'

export interface Oid4vciClientOptions {
  /**
   * Callbacks required for the oid4vc issuer
   */
  callbacks: Omit<CallbackContext, 'hash' | 'generateRandom' | 'clientAuthentication'>
}

export class Oid4vpClient {
  public constructor(private options: Oid4vciClientOptions) {}

  public parseOpenid4vpAuthorizationRequestPayload(options: ParseOpenid4vpAuthRequestPayloadOptions) {
    return parseOpenid4vpAuthorizationRequestPayload(options)
  }

  public async resolveOpenId4vpAuthorizationRequest(
    options: Omit<ResolveOpenid4vpAuthorizationRequestOptions, 'callbacks'>
  ) {
    return resolveOpenid4vpAuthorizationRequest({ ...options, callbacks: this.options.callbacks })
  }

  public async createOpenid4vpAuthorizationResponse(
    options: Omit<CreateOpenid4vpAuthorizationResponseOptions, 'callbacks'>
  ) {
    return createOpenid4vpAuthorizationResponse({ ...options, callbacks: this.options.callbacks })
  }

  public async submitOpenid4vpAuthorizationResponse(
    options: Omit<SubmitOpenid4vpAuthorizationResponseOptions, 'callbacks'>
  ) {
    return submitOpenid4vpAuthorizationResponse({ ...options, callbacks: this.options.callbacks })
  }
}
