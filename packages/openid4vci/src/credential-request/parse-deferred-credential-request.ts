import { parseWithErrorHandling } from '@openid4vc/utils'
import { type DeferredCredentialRequest, zDeferredCredentialRequest } from './z-credential-request'

export interface ParseDeferredCredentialRequestOptions {
  deferredCredentialRequest: Record<string, unknown>
}

export interface ParseDeferredCredentialRequestReturn {
  /**
   * The validated credential request. If both `format` and `credentialIdentifier` are
   * undefined you can still handle the request by using this object directly.
   */
  deferredCredentialRequest: DeferredCredentialRequest
}

export function parseDeferredCredentialRequest(
  options: ParseDeferredCredentialRequestOptions
): ParseDeferredCredentialRequestReturn {
  const deferredCredentialRequest = parseWithErrorHandling(
    zDeferredCredentialRequest,
    options.deferredCredentialRequest,
    'Error validating credential request'
  )

  return {
    deferredCredentialRequest,
  }
}
