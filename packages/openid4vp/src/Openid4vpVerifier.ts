import type { CallbackContext } from '@openid4vc/oauth2'
import {
  type CreateOpenid4vpAuthorizationRequestOptions,
  createOpenid4vpAuthorizationRequest,
} from './authorization-request/create-authorization-request'
import {
  type ParseOpenid4vpAuthorizationRequestPayloadOptions,
  parseOpenid4vpAuthorizationRequestPayload,
} from './authorization-request/parse-authorization-request-params'
import {
  type ParseOpenid4vpAuthorizationResponseOptions,
  parseOpenid4vpAuthorizationResponse,
} from './authorization-response/parse-authorization-response'
import {
  type ValidateOpenid4vpAuthorizationResponseOptions,
  validateOpenid4vpAuthorizationResponsePayload,
} from './authorization-response/validate-authorization-response'
import type { ParseTransactionDataOptions } from './transaction-data/parse-transaction-data'
import { parseTransactionData } from './transaction-data/parse-transaction-data'
import { type VerifyTransactionDataOptions, verifyTransactionData } from './transaction-data/verify-transaction-data'
import { parseDcqlVpToken, parsePexVpToken } from './vp-token/parse-vp-token'

export interface Openid4vpVerifierOptions {
  /**
   * Callbacks required for the openid4vp verifier
   */
  callbacks: Omit<CallbackContext, 'hash' | 'generateRandom' | 'clientAuthentication'>
}

export class Openid4vpVerifier {
  public constructor(private options: Openid4vpVerifierOptions) {}

  public async createOpenId4vpAuthorizationRequest(
    options: Omit<CreateOpenid4vpAuthorizationRequestOptions, 'callbacks'>
  ) {
    return createOpenid4vpAuthorizationRequest({ ...options, callbacks: this.options.callbacks })
  }

  public parseOpenid4vpAuthorizationRequestPayload(options: ParseOpenid4vpAuthorizationRequestPayloadOptions) {
    return parseOpenid4vpAuthorizationRequestPayload(options)
  }

  public parseOpenid4vpAuthorizationResponse(options: ParseOpenid4vpAuthorizationResponseOptions) {
    return parseOpenid4vpAuthorizationResponse(options)
  }

  public validateOpenid4vpAuthorizationResponsePayload(options: ValidateOpenid4vpAuthorizationResponseOptions) {
    return validateOpenid4vpAuthorizationResponsePayload(options)
  }

  public parsePexVpToken(vpToken: unknown) {
    return parsePexVpToken(vpToken)
  }

  public parseDcqlVpToken(vpToken: unknown) {
    return parseDcqlVpToken(vpToken)
  }

  public parseTransactionData(options: ParseTransactionDataOptions) {
    return parseTransactionData(options)
  }

  public verifyTransactionData(options: VerifyTransactionDataOptions) {
    return verifyTransactionData(options)
  }
}
