import {
  type CallbackContext,
  type Jwk,
  type JwtSigner,
  type JwtSignerWithJwk,
  Oauth2Error,
  Oauth2ErrorCodes,
  Oauth2ServerErrorResponseError,
  decodeJwt,
  jwtSignerFromJwt,
  verifyJwt,
  zCompactJwe,
  zCompactJwt,
} from '@openid4vc/oauth2'
import z from 'zod'
import { isOpenid4vpResponseModeDcApi } from '../../authorization-request/z-authorization-request-dc-api'
import { getOpenid4vpClientId } from '../../client-identifier-prefix/parse-client-identifier-prefix'
import {
  type ClientIdPrefix,
  type UniformClientIdPrefix,
  zClientIdPrefix,
} from '../../client-identifier-prefix/z-client-id-prefix'
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

const zSignedAuthorizationRequestJwtHeaderTyp = z.literal('oauth-authz-req+jwt')
export const signedAuthorizationRequestJwtHeaderTyp = zSignedAuthorizationRequestJwtHeaderTyp.value

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

  // We can't know the client id prefix here if draft was before client_id_scheme became prefix
  const clientIdPrefix: ClientIdPrefix | undefined = jarRequestParams.client_id
    ? zClientIdPrefix.safeParse(jarRequestParams.client_id.split(':')[0]).data
    : 'origin'

  const method = jarRequestParams.request_uri_method ?? 'get'
  if (method !== 'get' && method !== 'post') {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequestUriMethod,
      error_description: `Invalid request_uri_method. Must be 'get' or 'post'.`,
    })
  }

  const requestObject =
    jarRequestParams.request ??
    (await fetchJarRequestObject({
      requestUri: jarRequestParams.request_uri,
      clientIdPrefix,
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
      error_description: 'JAR request object is not a valid JWT.',
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

  // Expect the client_id from the jar request to match the payload, but only if we're not using DC API
  if (
    !isOpenid4vpResponseModeDcApi(authorizationRequestPayload.response_mode) &&
    jarRequestParams.client_id !== authorizationRequestPayload.client_id
  ) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: 'client_id does not match the request object client_id.',
    })
  }
  if (
    jarRequestParams.client_id_scheme &&
    jarRequestParams.client_id_scheme !== authorizationRequestPayload.client_id_scheme
  ) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: 'client_id_scheme does not match the request object client_id_scheme.',
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

  let jwtSigner: JwtSigner

  const { clientIdPrefix } = getOpenid4vpClientId({
    responseMode: jwt.payload.response_mode,
    clientId: jwt.payload.client_id,
    legacyClientIdScheme: jwt.payload.client_id_scheme,
  })

  // Allowed signer methods for each of the client id schemes
  const clientIdToSignerMethod: Record<UniformClientIdPrefix, JwtSigner['method'][]> = {
    decentralized_identifier: ['did'],

    'pre-registered': ['custom', 'did', 'jwk'],
    origin: [], // no signing allowed
    redirect_uri: [], // no signing allowed

    // Not 100% sure which one are allowed?
    verifier_attestation: ['did', 'federation', 'jwk', 'x5c', 'custom'],

    x509_san_dns: ['x5c'],
    x509_san_uri: ['x5c'],
    x509_hash: ['x5c'],

    // Handled separately
    openid_federation: [],
  }

  // The logic to determine the signer for a JWT is different for signed authorization request and federation
  if (clientIdPrefix === 'openid_federation') {
    if (!jwt.header.kid) {
      throw new Oauth2Error(
        `When OpenID Federation is used for signed authorization request, the 'kid' parameter is required.`
      )
    }

    jwtSigner = {
      method: 'federation',
      alg: jwt.header.alg,
      trustChain: jwt.payload.trust_chain,
      kid: jwt.header.kid,
    }
  } else {
    jwtSigner = jwtSignerFromJwt({ ...jwt, allowedSignerMethods: clientIdToSignerMethod[clientIdPrefix] })
  }

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
