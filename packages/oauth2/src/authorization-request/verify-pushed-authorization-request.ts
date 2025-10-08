import { JwtSigner } from '../common/jwt/z-jwt'
import { verifyJarRequest } from '../jar/handle-jar-request/verify-jar-request'
import {
  type VerifyAuthorizationRequestOptions,
  type VerifyAuthorizationRequestReturn,
  verifyAuthorizationRequest,
} from './verify-authorization-request'

export type VerifyPushedAuthorizationRequestReturn = VerifyAuthorizationRequestReturn
export interface VerifyPushedAuthorizationRequestOptions extends VerifyAuthorizationRequestOptions {
  authorizationRequestJwt?: {
    jwt: string,
    signer: JwtSigner
  }
}

export async function verifyPushedAuthorizationRequest(
  options: VerifyPushedAuthorizationRequestOptions
): Promise<VerifyPushedAuthorizationRequestReturn> {
  const { clientAttestation, dpop } = await verifyAuthorizationRequest(options)

  if(options.authorizationRequestJwt) {

    await verifyJarRequest({ 
      authorizationRequestJwt: options.authorizationRequestJwt.jwt,
      jarRequestParams: options.authorizationRequest, 
      callbacks: options.callbacks, 
      jwtSigner: options.authorizationRequestJwt.signer
    })
  }

  return {
    dpop,
    clientAttestation,
  }
}
