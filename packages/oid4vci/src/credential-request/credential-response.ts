import { parseWithErrorHandling } from '@animo-id/oid4vc-utils'
import { type CredentialResponse, vCredentialResponse } from './v-credential-response'

export interface CreateCredentialResponseOptions {
  credential?: CredentialResponse['credential']
  credentials?: CredentialResponse['credentials']

  cNonce?: string
  cNonceExpiresInSeconds?: number

  notificationId?: string

  /**
   * Additional payload to include in the credential response
   */
  additionalPayload?: Record<string, unknown>
}

export function createCredentialResponse(options: CreateCredentialResponseOptions) {
  const credentialResponse = parseWithErrorHandling(vCredentialResponse, {
    c_nonce: options.cNonce,
    c_nonce_expires_in: options.cNonceExpiresInSeconds,
    credential: options.credential,
    credentials: options.credentials,
    notification_id: options.notificationId,
    ...options.additionalPayload,
  } satisfies CredentialResponse)

  return credentialResponse
}
