import {
  type CallbackContext,
  Oauth2Error,
  decodeJwt,
  jwtSignerFromJwt,
  zCompactJwe,
  zCompactJwt,
  zJwtHeader,
} from '@openid4vc/oauth2'
import z from 'zod'
import type { Openid4vpAuthorizationRequest } from '../../authorization-request/z-authorization-request'
import type { Openid4vpAuthorizationRequestDcApi } from '../../authorization-request/z-authorization-request-dc-api'
import { extractJwksFromClientMetadata } from '../jarm-extract-jwks'
import { jarmAuthorizationResponseValidate } from './jarm-validate-authorization-response'
import {
  type JarmAuthorizationResponse,
  type JarmAuthorizationResponseEncryptedOnly,
  zJarmAuthorizationResponse,
  zJarmAuthorizationResponseEncryptedOnly,
} from './z-jarm-authorization-response'

export enum JarmMode {
  Signed = 'Signed',
  Encrypted = 'Encrypted',
  SignedEncrypted = 'SignedEncrypted',
}

/**
 * The client decrypts the JWT using the default key for the respective issuer or,
 * if applicable, determined by the kid JWT header parameter.
 * The key might be a private key, where the corresponding public key is registered
 * with the expected issuer of the response ("use":"enc" via the client's metadata jwks or jwks_uri)
 * or a key derived from its client secret (see Section 2.2).
 */
const decryptJarmAuthorizationResponseJwt = async (options: {
  jarmAuthorizationResponseJwt: string
  callbacks: Pick<CallbackContext, 'decryptJwe'>
  authorizationRequestPayload: Openid4vpAuthorizationRequest | Openid4vpAuthorizationRequestDcApi
}) => {
  const { jarmAuthorizationResponseJwt, callbacks, authorizationRequestPayload } = options

  // NOTE: previously we required `kid` to be present in the JARM header, but not all implementations seem to
  // add this, so we removed the check. For now we try to extract the JWK from the request, if we are not successfull
  // (because e.g. the request used client_metadata_uri) the decryptJwe callback has to handle this edge case
  // See https://github.com/openid/OpenID4VP/issues/441
  const encryptionJwk = authorizationRequestPayload.client_metadata?.jwks
    ? extractJwksFromClientMetadata({
        ...authorizationRequestPayload.client_metadata,
        jwks: authorizationRequestPayload.client_metadata.jwks,
      }).encJwk
    : undefined

  const result = await callbacks.decryptJwe(jarmAuthorizationResponseJwt, { jwk: encryptionJwk })
  if (!result.decrypted) {
    throw new Oauth2Error('Failed to decrypt jarm auth response.')
  }

  return result.payload
}

export interface VerifyJarmAuthorizationResponseOptions {
  jarmAuthorizationResponseJwt: string

  authorizationRequestPayload: Openid4vpAuthorizationRequest | Openid4vpAuthorizationRequestDcApi

  /**
   * The client id of the authorization request. This should be the effective client id,
   * meaning that if no client_id was present in the authorization request and DC API is used
   * it should be `web-origin:<origin>`
   */
  expectedClientId: string

  callbacks: Pick<CallbackContext, 'decryptJwe' | 'verifyJwt'>
}

export type VerifiedJarmAuthorizationResponse = Awaited<ReturnType<typeof verifyJarmAuthorizationResponse>>

/**
 * Validate a JARM direct_post.jwt compliant authentication response
 * * The decryption key should be resolvable using the the protected header's 'kid' field
 * * The signature verification jwk should be resolvable using the jws protected header's 'kid' field and the payload's 'iss' field.
 */
export async function verifyJarmAuthorizationResponse(options: VerifyJarmAuthorizationResponseOptions) {
  const { jarmAuthorizationResponseJwt, callbacks, expectedClientId, authorizationRequestPayload } = options

  const requestDataIsEncrypted = zCompactJwe.safeParse(jarmAuthorizationResponseJwt).success
  const decryptedRequestData = requestDataIsEncrypted
    ? await decryptJarmAuthorizationResponseJwt({
        jarmAuthorizationResponseJwt,
        callbacks,
        authorizationRequestPayload,
      })
    : jarmAuthorizationResponseJwt

  const responseIsSigned = zCompactJwt.safeParse(decryptedRequestData).success
  if (!requestDataIsEncrypted && !responseIsSigned) {
    throw new Oauth2Error('Jarm Auth Response must be either encrypted, signed, or signed and encrypted.')
  }

  let jarmAuthorizationResponse: JarmAuthorizationResponse | JarmAuthorizationResponseEncryptedOnly

  if (responseIsSigned) {
    const { header: jwsProtectedHeader, payload: jwsPayload } = decodeJwt({
      jwt: decryptedRequestData,
      headerSchema: z.object({ ...zJwtHeader.shape, kid: z.string() }),
    })

    const response = zJarmAuthorizationResponse.parse(jwsPayload)
    const jwtSigner = jwtSignerFromJwt({ header: jwsProtectedHeader, payload: jwsPayload })

    const verificationResult = await options.callbacks.verifyJwt(jwtSigner, {
      compact: decryptedRequestData,
      header: jwsProtectedHeader,
      payload: jwsPayload,
    })

    if (!verificationResult.verified) {
      throw new Oauth2Error('Jarm Auth Response is not valid.')
    }

    jarmAuthorizationResponse = response
  } else {
    const jsonRequestData: unknown = JSON.parse(decryptedRequestData)
    jarmAuthorizationResponse = zJarmAuthorizationResponseEncryptedOnly.parse(jsonRequestData)
  }

  jarmAuthorizationResponseValidate({
    expectedClientId,
    authorizationResponse: jarmAuthorizationResponse,
  })
  const type: JarmMode =
    requestDataIsEncrypted && responseIsSigned
      ? JarmMode.SignedEncrypted
      : requestDataIsEncrypted
        ? JarmMode.Encrypted
        : JarmMode.Signed

  const issuer = jarmAuthorizationResponse.iss
  return { jarmAuthorizationResponse, type, issuer }
}
