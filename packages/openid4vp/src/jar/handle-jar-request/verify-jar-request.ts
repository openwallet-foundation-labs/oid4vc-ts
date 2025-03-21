import {
  type CallbackContext,
  type Jwk,
  type JwtSignerWithJwk,
  Oauth2ErrorCodes,
  Oauth2ServerErrorResponseError,
  decodeJwt,
  jwtSignerFromJwt,
  verifyJwt,
  zCompactJwe,
  zCompactJwt,
} from '@openid4vc/oauth2'
import { type ClientIdScheme, zClientIdScheme } from '../../client-identifier-scheme/z-client-id-scheme'
import type { WalletMetadata } from '../../models/z-wallet-metadata'
import { parseAuthorizationRequestVersion } from '../../version'
import { fetchJarRequestObject } from '../jar-request-object/fetch-jar-request-object'
import { type JarRequestObjectPayload, zJarRequestObjectPayload } from '../jar-request-object/z-jar-request-object'
import { type JarAuthorizationRequest, validateJarRequestParams } from '../z-jar-authorization-request'

export interface VerifyJarRequestOptions {
  jarRequestParams: JarAuthorizationRequest
  callbacks: Pick<CallbackContext, 'verifyJwt' | 'decryptJwe' | 'fetch'>
  wallet?: {
    metadata?: WalletMetadata
    nonce?: string
  }
}

export interface VerifiedJarRequest {
  authorizationRequestPayload: JarRequestObjectPayload
  sendBy: 'value' | 'reference'
  decryptionJwk?: Jwk
  signer: JwtSignerWithJwk
  jwt: ReturnType<typeof decodeJwt<undefined, typeof zJarRequestObjectPayload>>
}

/**
 * Verifies a JAR (JWT Secured Authorization Request) request by validating, decrypting, and verifying signatures.
 *
 * @param options - The input parameters
 * @param options.jarRequestParams - The JAR authorization request parameters
 * @param options.callbacks - Context containing the relevant Jose crypto operations
 * @returns The verified authorization request parameters and metadata
 */
export async function verifyJarRequest(options: VerifyJarRequestOptions): Promise<VerifiedJarRequest> {
  const { callbacks, wallet = {} } = options

  const jarRequestParams = validateJarRequestParams(options)

  const sendBy = jarRequestParams.request ? 'value' : 'reference'

  // We can't know the client id scheme here if draft was before client_id_scheme became prefix
  const clientIdentifierScheme: ClientIdScheme | undefined = jarRequestParams.client_id
    ? zClientIdScheme.safeParse(jarRequestParams.client_id.split(':')[0]).data
    : 'web-origin'

  const method = jarRequestParams.request_uri_method ?? 'GET'
  if (method !== 'GET' && method !== 'POST') {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequestUriMethod,
      error_description: 'Invalid request_uri_method. Must be GET or POST.',
    })
  }

  const requestObject =
    jarRequestParams.request ??
    (await fetchJarRequestObject({
      requestUri: jarRequestParams.request_uri,
      clientIdentifierScheme,
      method,
      wallet,
      fetch: callbacks.fetch,
    }))

  const requestObjectIsEncrypted = zCompactJwe.safeParse(requestObject).success
  const { decryptionJwk, payload: decryptedRequestObject } = requestObjectIsEncrypted
    ? await decryptJarRequest({ jwe: requestObject, callbacks })
    : { payload: requestObject, decryptionJwk: undefined }

  const requestIsSigned = zCompactJwt.safeParse(decryptedRequestObject).success
  if (!requestIsSigned) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequestObject,
      error_description: 'Jar Request Object is not a valid JWS.',
    })
  }

  const { authorizationRequestPayload, signer, jwt } = await verifyJarRequestObject({
    decryptedRequestObject,
    callbacks,
  })
  if (!authorizationRequestPayload.client_id) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequestObject,
      error_description: 'Jar Request Object is missing the required "client_id" field.',
    })
  }

  if (jarRequestParams.client_id !== authorizationRequestPayload.client_id) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: 'client_id does not match the request object client_id.',
    })
  }

  return {
    sendBy,
    jwt,
    authorizationRequestPayload,
    signer,
    decryptionJwk,
  }
}

async function decryptJarRequest(options: {
  jwe: string
  callbacks: Pick<CallbackContext, 'decryptJwe'>
}) {
  const { jwe, callbacks } = options

  const { header } = decodeJwt({ jwt: jwe })
  if (!header.kid) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequestObject,
      error_description: 'Jar JWE is missing the protected header field "kid".',
    })
  }

  const decryptionResult = await callbacks.decryptJwe(jwe)
  if (!decryptionResult.decrypted) {
    throw new Oauth2ServerErrorResponseError({
      error: 'invalid_request_object',
      error_description: 'Failed to decrypt jar request object.',
    })
  }

  return decryptionResult
}

async function verifyJarRequestObject(options: {
  decryptedRequestObject: string
  callbacks: Pick<CallbackContext, 'verifyJwt'>
}) {
  const { decryptedRequestObject, callbacks } = options

  const jwt = decodeJwt({ jwt: decryptedRequestObject, payloadSchema: zJarRequestObjectPayload })
  const jwtSigner = jwtSignerFromJwt(jwt)
  const { signer } = await verifyJwt({
    verifyJwtCallback: callbacks.verifyJwt,
    compact: decryptedRequestObject,
    header: jwt.header,
    payload: jwt.payload,
    signer: jwtSigner,
  })

  // biome-ignore lint/suspicious/noExplicitAny: <explanation>
  const version = parseAuthorizationRequestVersion(jwt.payload as any)
  if (jwt.header.typ !== 'oauth-authz-req+jwt' && version >= 24) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequestObject,
      error_description: `Invalid Jar Request Object typ header. Expected "oauth-authz-req+jwt", received "${jwt.header.typ}".`,
    })
  }

  return {
    signer,
    jwt,
    authorizationRequestPayload: jwt.payload,
  }
}
