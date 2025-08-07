import { parseWithErrorHandling } from '@openid4vc/utils'
import type { ParseCredentialRequestReturn } from './parse-credential-request'
import {
  type CredentialResponse,
  type DeferredCredentialResponse,
  zCredentialResponse,
  zDeferredCredentialResponse,
} from './z-credential-response'

export interface CreateCredentialResponseOptions {
  credentialRequest: ParseCredentialRequestReturn

  credential?: CredentialResponse['credential']
  credentials?: CredentialResponse['credentials']

  transactionId?: string
  interval?: number

  cNonce?: string
  cNonceExpiresInSeconds?: number

  notificationId?: string

  /**
   * Additional payload to include in the credential response
   */
  additionalPayload?: Record<string, unknown>
}

export function createCredentialResponse(options: CreateCredentialResponseOptions) {
  const credentialResponse = parseWithErrorHandling(zCredentialResponse, {
    c_nonce: options.cNonce,
    c_nonce_expires_in: options.cNonceExpiresInSeconds,
    credential: options.credential,
    credentials: options.credentials,
    notification_id: options.notificationId,

    transaction_id: options.transactionId,
    interval: options.interval,

    // NOTE `format` is removed in draft 13. For now if a format was requested
    // we just always return it in the response as well.
    format: options.credentialRequest.format?.format,
    ...options.additionalPayload,
  } satisfies CredentialResponse)

  return credentialResponse
}

export type CreateDeferredCredentialResponseOptions = Omit<
  CreateCredentialResponseOptions,
  'credentialRequest' | 'transactionId' | 'cNonce' | 'cNonceExpiresInSeconds'
>

export function createDeferredCredentialResponse(options: CreateDeferredCredentialResponseOptions) {
  return parseWithErrorHandling(zDeferredCredentialResponse, {
    credential: options.credential,
    credentials: options.credentials,
    notification_id: options.notificationId,
    interval: options.interval,
    ...options.additionalPayload,
  } satisfies DeferredCredentialResponse)
}
