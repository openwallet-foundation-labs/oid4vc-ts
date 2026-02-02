import type { CallbackContext, JweEncryptor } from '@openid4vc/oauth2'
import { parseWithErrorHandling } from '@openid4vc/utils'
import { Openid4vciError } from '../error/Openid4vciError'
import type { ParseCredentialRequestReturn } from './parse-credential-request'
import type { CredentialResponseEncryption } from './z-credential-request-common'
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

  /**
   * Encryption parameters from the credential request. When provided along with
   * the `encryptJwe` callback, the credential response will be encrypted as a JWE.
   *
   * You can pass `credentialRequest.credentialResponseEncryption` from the parsed
   * credential request directly to this option.
   */
  credentialResponseEncryption?: CredentialResponseEncryption

  /**
   * Callbacks for credential response operations.
   * Required when `credentialResponseEncryption` is provided.
   */
  callbacks?: Pick<CallbackContext, 'encryptJwe'>
}

export interface CreateCredentialResponseReturn {
  /**
   * The credential response object (before encryption).
   */
  credentialResponse: CredentialResponse

  /**
   * The credential response as a JWE string if encryption was requested.
   * When this is defined, the response should be returned with `Content-Type: application/jwt`.
   */
  credentialResponseJwt?: string
}

export async function createCredentialResponse(
  options: CreateCredentialResponseOptions
): Promise<CreateCredentialResponseReturn> {
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

  // If encryption is requested, encrypt the response
  if (options.credentialResponseEncryption) {
    if (!options.callbacks?.encryptJwe) {
      throw new Openid4vciError(
        `'credentialResponseEncryption' was provided but 'callbacks.encryptJwe' is not defined. ` +
          `Provide the 'encryptJwe' callback to encrypt the credential response.`
      )
    }

    const jweEncryptor: JweEncryptor = {
      method: 'jwk',
      publicJwk: options.credentialResponseEncryption.jwk,
      alg: options.credentialResponseEncryption.alg,
      enc: options.credentialResponseEncryption.enc,
    }

    const { jwe } = await options.callbacks.encryptJwe(jweEncryptor, JSON.stringify(credentialResponse))

    return {
      credentialResponse,
      credentialResponseJwt: jwe,
    }
  }

  return {
    credentialResponse,
  }
}

export type CreateDeferredCredentialResponseOptions = (
  | {
      credentials: DeferredCredentialResponse['credentials']
      notificationId?: string

      transactionId?: never
      interval?: never
    }
  | {
      /**
       * The `transaction_id` used to identify the deferred issuance transaction.
       */
      transactionId: string
      interval: number

      credentials?: never
      notificationId?: never
    }
) & {
  /**
   * Additional payload to include in the deferred credential response
   */
  additionalPayload?: Record<string, unknown>

  /**
   * Encryption parameters from the deferred credential request. When provided along with
   * the `encryptJwe` callback, the deferred credential response will be encrypted as a JWE.
   *
   * You can pass `deferredCredentialRequest.credential_response_encryption` from the parsed
   * deferred credential request directly to this option.
   */
  credentialResponseEncryption?: CredentialResponseEncryption

  /**
   * Callbacks for credential response operations.
   * Required when `credentialResponseEncryption` is provided.
   */
  callbacks?: Pick<CallbackContext, 'encryptJwe'>
}

export interface CreateDeferredCredentialResponseReturn {
  /**
   * The deferred credential response object (before encryption).
   */
  deferredCredentialResponse: DeferredCredentialResponse

  /**
   * The deferred credential response as a JWE string if encryption was requested.
   * When this is defined, the response should be returned with `Content-Type: application/jwt`.
   */
  deferredCredentialResponseJwt?: string
}

export async function createDeferredCredentialResponse(
  options: CreateDeferredCredentialResponseOptions
): Promise<CreateDeferredCredentialResponseReturn> {
  const deferredCredentialResponse = parseWithErrorHandling(zDeferredCredentialResponse, {
    credentials: options.credentials,
    notification_id: options.notificationId,

    transaction_id: options.transactionId,
    interval: options.interval,

    ...options.additionalPayload,
  } satisfies DeferredCredentialResponse)

  // If encryption is requested, encrypt the response
  if (options.credentialResponseEncryption) {
    if (!options.callbacks?.encryptJwe) {
      throw new Openid4vciError(
        `'credentialResponseEncryption' was provided but 'callbacks.encryptJwe' is not defined. ` +
          `Provide the 'encryptJwe' callback to encrypt the deferred credential response.`
      )
    }

    const jweEncryptor: JweEncryptor = {
      method: 'jwk',
      publicJwk: options.credentialResponseEncryption.jwk,
      alg: options.credentialResponseEncryption.alg,
      enc: options.credentialResponseEncryption.enc,
    }

    const { jwe } = await options.callbacks.encryptJwe(jweEncryptor, JSON.stringify(deferredCredentialResponse))

    return {
      deferredCredentialResponse,
      deferredCredentialResponseJwt: jwe,
    }
  }

  return {
    deferredCredentialResponse,
  }
}
