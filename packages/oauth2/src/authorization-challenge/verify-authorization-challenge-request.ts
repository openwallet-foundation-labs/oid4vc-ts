import {
  type VerifyAuthorizationRequestOptions,
  type VerifyAuthorizationRequestReturn,
  verifyAuthorizationRequest,
} from '../authorization-request/verify-authorization-request'
import type { AuthorizationChallengeRequest } from './z-authorization-challenge'

export type VerifyAuthorizationChallengeRequestReturn = VerifyAuthorizationRequestReturn
export interface VerifyAuthorizationChallengeRequestOptions
  extends Omit<VerifyAuthorizationRequestOptions, 'authorizationRequest'> {
  authorizationChallengeRequest: AuthorizationChallengeRequest
}

export async function verifyAuthorizationChallengeRequest(
  options: VerifyAuthorizationChallengeRequestOptions
): Promise<VerifyAuthorizationChallengeRequestReturn> {
  const { clientAttestation, dpop } = await verifyAuthorizationRequest({
    ...options,
    authorizationRequest: options.authorizationChallengeRequest,
  })

  return {
    dpop,
    clientAttestation,
  }
}
