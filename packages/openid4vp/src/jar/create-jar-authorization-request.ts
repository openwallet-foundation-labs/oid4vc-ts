import {
  type CallbackContext,
  type JweEncryptor,
  type Jwk,
  type JwtPayload,
  type JwtSigner,
  jwtHeaderFromJwtSigner,
} from '@openid4vc/oauth2'
import { addSecondsToDate, dateToSeconds } from '@openid4vc/utils'
import type { JarAuthorizationRequest } from './z-jar-authorization-request'

export interface CreateJarAuthorizationRequestOptions {
  authorizationRequestPayload: JwtPayload & { client_id?: string }
  requestUri?: string

  jwtSigner: JwtSigner
  jweEncryptor?: JweEncryptor

  callbacks: Pick<CallbackContext, 'signJwt' | 'encryptJwe'>

  /**
   * Number of seconds after which the signed authorization request will expire
   */
  expiresInSeconds: number

  /**
   * Date that should be used as now. If not provided current date will be used.
   */
  now?: Date

  additionalJwtPayload?: Record<string, unknown>
}

/**
 * Creates a JAR (JWT Authorization Request) request object.
 *
 * @param options - The input parameters
 * @param options.authorizationRequestPayload - The authorization request parameters
 * @param options.jwtSigner - The JWT signer
 * @param options.jweEncryptor - The JWE encryptor (optional) if provided, the request object will be encrypted
 * @param options.requestUri - The request URI (optional) if provided, the request object needs to be fetched from the URI
 * @param options.callbacks - The callback context
 * @returns the requestParams, signerJwk, encryptionJwk, and requestObjectJwt
 */
export async function createJarAuthorizationRequest(options: CreateJarAuthorizationRequestOptions) {
  const { jwtSigner, jweEncryptor, authorizationRequestPayload, requestUri, callbacks } = options

  let authorizationRequestJwt: string | undefined
  let encryptionJwk: Jwk | undefined

  const now = options.now ?? new Date()

  const { jwt, signerJwk } = await callbacks.signJwt(jwtSigner, {
    header: { ...jwtHeaderFromJwtSigner(jwtSigner), typ: 'oauth-authz-req+jwt' },
    payload: {
      iat: dateToSeconds(now),
      exp: dateToSeconds(addSecondsToDate(now, options.expiresInSeconds)),
      ...options.additionalJwtPayload,
      ...authorizationRequestPayload,
    },
  })
  authorizationRequestJwt = jwt

  if (jweEncryptor) {
    const encryptionResult = await callbacks.encryptJwe(jweEncryptor, authorizationRequestJwt)
    authorizationRequestJwt = encryptionResult.jwe
    encryptionJwk = encryptionResult.encryptionJwk
  }

  const client_id = authorizationRequestPayload.client_id
  const jarAuthorizationRequest: JarAuthorizationRequest = requestUri
    ? { client_id, request_uri: requestUri }
    : { client_id, request: authorizationRequestJwt }

  return { jarAuthorizationRequest, signerJwk, encryptionJwk, authorizationRequestJwt }
}
