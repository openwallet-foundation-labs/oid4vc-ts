import type { JwtSigner } from '../common/jwt/z-jwt'
import { type VerifiedJarRequest, verifyJarRequest } from '../jar/handle-jar-request/verify-jar-request'
import {
  type VerifyAuthorizationRequestOptions,
  type VerifyAuthorizationRequestReturn,
  verifyAuthorizationRequest,
} from './verify-authorization-request'

export interface VerifyPushedAuthorizationRequestReturn extends VerifyAuthorizationRequestReturn {
  /**
   * The verified JAR request, if `authorizationRequestJwt` was provided
   */
  jar?: VerifiedJarRequest
}

export interface VerifyPushedAuthorizationRequestOptions extends VerifyAuthorizationRequestOptions {
  /**
   * The authorization request JWT to verify. If this value was returned from `parsePushedAuthorizationRequest`
   * you MUST provide this value to ensure the JWT is verified.
   */
  authorizationRequestJwt?: {
    jwt: string
    signer: JwtSigner
  }
}

export async function verifyPushedAuthorizationRequest(
  options: VerifyPushedAuthorizationRequestOptions
): Promise<VerifyPushedAuthorizationRequestReturn> {
  let jar: VerifiedJarRequest | undefined
  if (options.authorizationRequestJwt) {
    jar = await verifyJarRequest({
      authorizationRequestJwt: options.authorizationRequestJwt.jwt,
      jarRequestParams: options.authorizationRequest,
      callbacks: options.callbacks,
      jwtSigner: options.authorizationRequestJwt.signer,
    })
  }

  const { clientAttestation, dpop } = await verifyAuthorizationRequest(options)

  return {
    dpop,
    clientAttestation,
    jar,
  }
}
