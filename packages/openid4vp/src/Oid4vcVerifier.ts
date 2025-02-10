import type { CallbackContext } from '@openid4vc/oauth2'
import {
  type CreateOpenid4vpAuthorizationRequestOptions,
  createOpenid4vpAuthorizationRequest,
} from './authorization-request/create-authorization-request'
import {
  type ParseOpenid4vpAuthRequestPayloadOptions,
  parseOpenid4vpAuthorizationRequestPayload,
} from './authorization-request/parse-authorization-request-params'
import {} from './authorization-request/resolve-authorization-request'
import {
  type ParseOpenid4vpAuthorizationResponseOptions,
  parseOpenid4vpAuthorizationResponse,
} from './authorization-response/parse-authorization-response'
import {
  type ValidateOpenid4vpAuthorizationResponseOptions,
  validateOpenid4vpAuthorizationResponse,
} from './authorization-response/validate-authorization-response'
import type { ParseTransactionDataOptions } from './transaction-data/parse-transaction-data'
import { parseTransactionData } from './transaction-data/parse-transaction-data'
import {
  type ParsePresentationsFromVpTokenOptions,
  parsePresentationsFromVpToken,
} from './vp-token/parse-presentations-from-vp-token'

export interface Oid4vciVerifierOptions {
  /**
   * Callbacks required for the oid4vc issuer
   */
  callbacks: Omit<CallbackContext, 'hash' | 'generateRandom' | 'clientAuthentication'>
}

export class Oid4vcVerifier {
  public constructor(private options: Oid4vciVerifierOptions) {}

  public async createOpenId4vpAuthorizationRequest(
    options: Omit<CreateOpenid4vpAuthorizationRequestOptions, 'callbacks'>
  ) {
    return createOpenid4vpAuthorizationRequest({ ...options, callbacks: this.options.callbacks })
  }

  public parseOpenid4vpAuthorizationRequestPayload(options: ParseOpenid4vpAuthRequestPayloadOptions) {
    return parseOpenid4vpAuthorizationRequestPayload(options)
  }

  public parseOpenid4vpAuthorizationResponse(options: ParseOpenid4vpAuthorizationResponseOptions) {
    return parseOpenid4vpAuthorizationResponse(options)
  }

  public validateOpenid4vpAuthorizationResponse(options: ValidateOpenid4vpAuthorizationResponseOptions) {
    return validateOpenid4vpAuthorizationResponse(options)
  }

  public parsePresentationsFromVpToken(options: ParsePresentationsFromVpTokenOptions) {
    return parsePresentationsFromVpToken(options)
  }

  public parseTransactionData(options: ParseTransactionDataOptions) {
    return parseTransactionData(options)
  }
}
