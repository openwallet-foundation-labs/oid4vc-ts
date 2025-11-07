import type {
  VerifyAuthorizationRequestOptions,
  VerifyAuthorizationRequestReturn,
} from '../authorization-request/verify-authorization-request.js'
import { verifyAuthorizationRequest } from '../authorization-request/verify-authorization-request.js'
import type {
  InteractiveAuthorizationFollowUpRequest,
  InteractiveAuthorizationRequest,
} from './z-interactive-authorization.js'

export type VerifyInteractiveAuthorizationRequestReturn = VerifyAuthorizationRequestReturn

export interface VerifyInteractiveAuthorizationRequestOptions
  extends Omit<VerifyAuthorizationRequestOptions, 'authorizationRequest'> {
  /**
   * The parsed interactive authorization request to verify
   */
  interactiveAuthorizationRequest: InteractiveAuthorizationRequest | InteractiveAuthorizationFollowUpRequest

  /**
   * Indicates if this is a follow-up request
   * Follow-up requests may have different verification requirements
   */
  isFollowUpRequest: boolean
}

/**
 * Verify an Interactive Authorization Request
 *
 * This function verifies the interactive authorization request including:
 * - Client attestation (if present)
 * - DPoP binding (if present)
 * - Authorization request parameters (for initial requests)
 *
 * For follow-up requests, the verification is lighter as most parameters
 * have already been verified in the initial request.
 *
 * @param options - Verification options
 * @returns Verification result with client attestation and DPoP info
 *
 * @example Verify initial request
 * ```ts
 * const result = await verifyInteractiveAuthorizationRequest({
 *   interactiveAuthorizationRequest: request,
 *   isFollowUpRequest: false,
 *   authorizationServerMetadata,
 *   fetch
 * })
 * ```
 */
export async function verifyInteractiveAuthorizationRequest(
  options: VerifyInteractiveAuthorizationRequestOptions
): Promise<VerifyInteractiveAuthorizationRequestReturn> {
  const { interactiveAuthorizationRequest, isFollowUpRequest } = options

  // For follow-up requests, we have minimal parameters to verify
  // The main verification should be done on the auth_session by the AS
  if (isFollowUpRequest) {
    // For follow-up requests, client attestation/DPoP are typically not present
    // since they were already verified in the initial request
    return {
      dpop: undefined,
      clientAttestation: undefined,
    }
  }

  // For initial requests, perform full verification
  const { clientAttestation, dpop } = await verifyAuthorizationRequest({
    ...options,
    authorizationRequest: interactiveAuthorizationRequest as InteractiveAuthorizationRequest,
  })

  return {
    dpop,
    clientAttestation,
  }
}
