import * as v from 'valibot'

import {
  type CallbackContext,
  type Jwk,
  type JwtSigner,
  Oauth2Error,
  Oauth2ServerErrorResponseError,
  decodeJwt,
  jwtSignerFromJwt,
  vCompactJwe,
  vCompactJwt,
} from '@openid4vc/oauth2'
import type { WalletMetadata } from '../../models/v-wallet-metadata'
import { fetchJarRequestObject } from '../jar-request-object/fetch-jar-request-object'
import { type JarRequestObjectPayload, vJarRequestObjectPayload } from '../jar-request-object/v-jar-request-object'
import { type JarAuthRequest, validateJarAuthRequest } from '../v-jar-auth-request'

/**
 * Verifies a JAR (JWT Secured Authorization Request) request by validating, decrypting, and verifying signatures.
 *
 * @param options - The input parameters
 * @param options.jarRequestParams - The JAR authorization request parameters
 * @param options.callbacks - Context containing the relevant Jose crypto operations
 * @returns The verified authorization request parameters and metadata
 */
export async function verifyJarRequest(options: {
  jarRequestParams: JarAuthRequest
  callbacks: Pick<CallbackContext, 'verifyJwt' | 'decryptJwt'>
  wallet?: {
    metadata?: WalletMetadata
    nonce?: string
  }
}): Promise<{
  authRequestParams: JarRequestObjectPayload
  sendBy: 'value' | 'reference'
  decryptionJwk?: Jwk
  signerJwk: Jwk
  jwtSigner: JwtSigner
}> {
  const { jarRequestParams, callbacks, wallet } = options

  validateJarAuthRequest({ jarAuthRequest: jarRequestParams })

  const sendBy = jarRequestParams.request ? 'value' : 'reference'

  const requestObject =
    jarRequestParams.request ??
    (await fetchJarRequestObject(
      // biome-ignore lint/style/noNonNullAssertion:
      jarRequestParams.request_uri!,
      jarRequestParams.client_id.split(':')[0],
      jarRequestParams.request_uri_method ?? 'GET',
      wallet ?? {}
    ))

  const requestObjectIsEncrypted = v.is(vCompactJwe, requestObject as string)
  const { decryptionJwk, payload: decryptedRequestObject } = requestObjectIsEncrypted
    ? await decryptJarRequest({ jwe: requestObject, callbacks })
    : { payload: requestObject, decryptionJwk: undefined }

  const requestIsSigned = v.parse(vCompactJwt, decryptedRequestObject)
  if (!requestIsSigned) {
    throw new Oauth2Error('Jar Request Object is not a valid JWS.')
  }

  const { authRequestParams, signerJwk, jwtSigner } = await verifyJarRequestObject({
    decryptedRequestObject,
    callbacks,
  })
  if (!authRequestParams.client_id) {
    throw new Oauth2Error('Jar Request Object is missing the required "client_id" field.')
  }

  if (jarRequestParams.client_id !== authRequestParams.client_id) {
    throw new Oauth2Error('client_id does not match the request object client_id.')
  }

  return {
    sendBy,
    authRequestParams,
    signerJwk,
    decryptionJwk,
    jwtSigner,
  }
}

async function decryptJarRequest(options: {
  jwe: string
  callbacks: Pick<CallbackContext, 'decryptJwt'>
}) {
  const { jwe, callbacks } = options

  const { header } = decodeJwt({ jwt: jwe })
  if (!header.kid) {
    throw new Oauth2Error('Jar JWE is missing the protected header field "kid".')
  }

  const decryptionResult = await callbacks.decryptJwt(jwe)
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

  const jwt = decodeJwt({ jwt: decryptedRequestObject, payloadSchema: vJarRequestObjectPayload })

  const jwtSigner = jwtSignerFromJwt(jwt)
  const { verified, signerJwk } = await callbacks.verifyJwt(jwtSigner, {
    ...jwt,
    compact: decryptedRequestObject,
  })

  if (!verified) {
    throw new Oauth2Error('Jar Request Object signature verification failed.')
  }

  return { authRequestParams: jwt.payload, signerJwk, jwtSigner }
}
