import { verifyJarRequest } from '../jar/handle-jar-request/verify-jar-request'
import {
  type VerifyAuthorizationRequestOptions,
  type VerifyAuthorizationRequestReturn,
  verifyAuthorizationRequest,
} from './verify-authorization-request'

export type VerifyPushedAuthorizationRequestReturn = VerifyAuthorizationRequestReturn
export interface VerifyPushedAuthorizationRequestOptions extends VerifyAuthorizationRequestOptions {
  jwtRequestObject?: string
}

export async function verifyPushedAuthorizationRequest(
  options: VerifyPushedAuthorizationRequestOptions
): Promise<VerifyPushedAuthorizationRequestReturn> {
  const { clientAttestation, dpop } = await verifyAuthorizationRequest(options)

  if(options.jwtRequestObject) {
    const clientPayload = clientAttestation?.clientAttestation?.payload
    if (!clientPayload) {
      throw new Error('Missing client-attestation payload while verifying JAR')
    }

    await verifyJarRequest({ 
      jwtRequestObject: options.jwtRequestObject,
      jarRequestParams: options.authorizationRequest, 
      callbacks: options.callbacks, 
      clientAttestationPayload: clientPayload
    })
  }

  return {
    dpop,
    clientAttestation,
  }
}
