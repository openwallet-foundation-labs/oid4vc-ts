import {
  type VerifyAuthorizationRequestOptions,
  type VerifyAuthorizationRequestReturn,
  verifyAuthorizationRequest,
} from './verify-authorization-request'
import type { AuthorizationRequest } from './z-authorization-request'

export type VerifyPushedAuthorizationRequestReturn = VerifyAuthorizationRequestReturn
export interface VerifyPushedAuthorizationRequestOptions extends VerifyAuthorizationRequestOptions {
  authorizationRequest: AuthorizationRequest
}

export async function verifyPushedAuthorizationRequest(
  options: VerifyPushedAuthorizationRequestOptions
): Promise<VerifyPushedAuthorizationRequestReturn> {
  const { clientAttestation, dpop } = await verifyAuthorizationRequest(options)

  return {
    dpop,
    clientAttestation,
  }
}
