import {
  type JwtSigner,
  type VerifiedJarRequest,
  type VerifyAuthorizationRequestOptions,
  type VerifyAuthorizationRequestReturn,
  verifyAuthorizationRequest,
  verifyJarRequest,
} from '@openid4vc/oauth2'
import type { InteractiveAuthorizationInitialRequest } from './z-interactive-authorization.js'

export interface VerifyInteractiveAuthorizationInitialRequestReturn extends VerifyAuthorizationRequestReturn {
  /**
   * The verified JAR request, if `interactiveAuthorizationRequestJwt` was provided
   */
  jar?: VerifiedJarRequest
}

export interface VerifyInteractiveAuthorizationInitialRequestOptions
  extends Omit<VerifyAuthorizationRequestOptions, 'authorizationRequest'> {
  /**
   * The parsed interactive authorization request to verify
   * Can be initial request or JAR request, but not a follow-up request
   */
  interactiveAuthorizationRequest: InteractiveAuthorizationInitialRequest

  /**
   * The interactive authorization request JWT to verify. If this value was returned from `parseInteractiveAuthorizationRequest`
   * you MUST provide this value to ensure the JWT is verified.
   */
  interactiveAuthorizationRequestJwt?: {
    jwt: string
    signer: JwtSigner
  }
}

/**
 * Verify an initial (possibly signed) Interactive Authorization Request
 *
 * This function verifies the interactive authorization request including:
 * - JAR (JWT-secured Authorization Request) signature verification (if present)
 * - Client attestation (if present)
 * - DPoP binding (if present)
 * - Authorization request parameters
 *
 * @param options - Verification options
 * @returns Verification result with client attestation and DPoP info
 *
 * @example Verify initial request
 * ```ts
 * const result = await verifyInteractiveAuthorizationInitialRequest({
 *   interactiveAuthorizationRequest: request,
 *   authorizationServerMetadata,
 *   callbacks: { fetch, verifyJwt }
 * })
 * ```
 *
 * @example Verify JAR request
 * ```ts
 * const result = await verifyInteractiveAuthorizationInitialRequest({
 *   interactiveAuthorizationRequest: jarRequest,
 *   interactiveAuthorizationRequestJwt: jwt,
 *   jwtSigner: { ... },
 *   authorizationServerMetadata,
 *   callbacks: { fetch, verifyJwt }
 * })
 * ```
 */
export async function verifyInteractiveAuthorizationInitialRequest(
  options: VerifyInteractiveAuthorizationInitialRequestOptions
): Promise<VerifyInteractiveAuthorizationInitialRequestReturn> {
  let jar: VerifiedJarRequest | undefined

  // Check if this is a JAR request that needs verification
  if (options.interactiveAuthorizationRequestJwt) {
    jar = await verifyJarRequest({
      authorizationRequestJwt: options.interactiveAuthorizationRequestJwt.jwt,
      jarRequestParams: options.interactiveAuthorizationRequest,
      callbacks: options.callbacks,
      jwtSigner: options.interactiveAuthorizationRequestJwt.signer,
    })
  }

  const { clientAttestation, dpop } = await verifyAuthorizationRequest({
    ...options,
    authorizationRequest: options.interactiveAuthorizationRequest,
  })

  return {
    dpop,
    clientAttestation,
    jar,
  }
}
