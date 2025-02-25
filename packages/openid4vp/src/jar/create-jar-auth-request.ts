import {
  type CallbackContext,
  type JweEncryptor,
  type Jwk,
  type JwtPayload,
  type JwtSigner,
  jwtHeaderFromJwtSigner,
} from '@openid4vc/oauth2'
import type { JarAuthRequest } from './z-jar-auth-request'

export interface CreateJarAuthRequestOptions {
  authRequestParams: JwtPayload & { client_id?: string }
  jwtSigner: JwtSigner
  jweEncryptor?: JweEncryptor
  requestUri?: string
  additionalJwtPayload?: Record<string, unknown>
  callbacks: Pick<CallbackContext, 'signJwt' | 'encryptJwe'>
}

/**
 * Creates a JAR (JWT Authorization Request) request object.
 *
 * @param options - The input parameters
 * @param options.authRequestParams - The authorization request parameters
 * @param options.jwtSigner - The JWT signer
 * @param options.jweEncryptor - The JWE encryptor (optional) if provided, the request object will be encrypted
 * @param options.requestUri - The request URI (optional) if provided, the request object needs to be fetched from the URI
 * @param options.callbacks - The callback context
 * @returns the requestParams, signerJwk, encryptionJwk, and requestObjectJwt
 */
export async function createJarAuthRequest(options: CreateJarAuthRequestOptions) {
  const { jwtSigner, jweEncryptor, authRequestParams, requestUri, callbacks } = options

  let requestObjectJwt: string | undefined
  let encryptionJwk: Jwk | undefined

  const { jwt, signerJwk } = await callbacks.signJwt(jwtSigner, {
    header: { ...jwtHeaderFromJwtSigner(jwtSigner), typ: 'oauth-authz-req+jwt' },
    payload: { ...options.additionalJwtPayload, ...authRequestParams },
  })
  requestObjectJwt = jwt

  if (jweEncryptor) {
    const encryptionResult = await callbacks.encryptJwe(jweEncryptor, requestObjectJwt)
    requestObjectJwt = encryptionResult.jwe
    encryptionJwk = encryptionResult.encryptionJwk
  }

  const client_id = authRequestParams.client_id
  const requestParams: JarAuthRequest = requestUri
    ? { client_id, request_uri: requestUri }
    : { client_id, request: requestObjectJwt }

  return { requestParams, signerJwk, encryptionJwk, requestObjectJwt }
}
