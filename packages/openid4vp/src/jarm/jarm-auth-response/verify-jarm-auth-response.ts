import {
  type CallbackContext,
  Oauth2Error,
  decodeJwt,
  decodeJwtHeader,
  jwtSignerFromJwt,
  zCompactJwe,
  zCompactJwt,
  zJwtHeader,
} from '@openid4vc/oauth2'
import z from 'zod'
import { jarmAuthResponseValidate } from './jarm-validate-auth-response'
import {
  type JarmAuthResponse,
  type JarmAuthResponseEncryptedOnly,
  zJarmAuthResponse,
  zJarmAuthResponseEncryptedOnly,
} from './z-jarm-auth-response'

export enum JarmMode {
  Signed = 'Signed',
  Encrypted = 'Encrypted',
  SignedEncrypted = 'SignedEncrypted',
}

export type GetOpenid4vpAuthorizationRequestCallback = (
  authResponse: JarmAuthResponse | JarmAuthResponseEncryptedOnly
) => Promise<{ authorizationRequest: { client_id: string; nonce: string; state?: string } }>

/**
 * The client decrypts the JWT using the default key for the respective issuer or,
 * if applicable, determined by the kid JWT header parameter.
 * The key might be a private key, where the corresponding public key is registered
 * with the expected issuer of the response ("use":"enc" via the client's metadata jwks or jwks_uri)
 * or a key derived from its client secret (see Section 2.2).
 */
const decryptJarmRequestData = async (options: {
  requestData: string
  callbacks: Pick<CallbackContext, 'decryptJwe'>
}) => {
  const { requestData, callbacks } = options

  const { header } = decodeJwtHeader({ jwt: requestData })
  if (!header.kid) {
    throw new Oauth2Error('Jarm JWE is missing the protected header field "kid".')
  }

  const result = await callbacks.decryptJwe(requestData)
  if (!result.decrypted) {
    throw new Oauth2Error('Failed to decrypt jarm auth response.')
  }

  return result.payload
}

export interface VerifyJarmAuthorizationResponseOptions {
  jarmAuthorizationResponseJwt: string
  callbacks: Pick<CallbackContext, 'decryptJwe' | 'verifyJwt'> & {
    getOpenid4vpAuthorizationRequest: GetOpenid4vpAuthorizationRequestCallback
  }
}

export type VerifiedJarmAuthorizationResponse = Awaited<ReturnType<typeof verifyJarmAuthorizationResponse>>

/**
 * Validate a JARM direct_post.jwt compliant authentication response
 * * The decryption key should be resolvable using the the protected header's 'kid' field
 * * The signature verification jwk should be resolvable using the jws protected header's 'kid' field and the payload's 'iss' field.
 */
export async function verifyJarmAuthorizationResponse(options: VerifyJarmAuthorizationResponseOptions) {
  const { jarmAuthorizationResponseJwt, callbacks } = options

  const requestDataIsEncrypted = zCompactJwe.safeParse(jarmAuthorizationResponseJwt).success
  const decryptedRequestData = requestDataIsEncrypted
    ? await decryptJarmRequestData({ requestData: jarmAuthorizationResponseJwt, callbacks })
    : jarmAuthorizationResponseJwt

  const responseIsSigned = zCompactJwt.safeParse(decryptedRequestData).success
  if (!requestDataIsEncrypted && !responseIsSigned) {
    throw new Oauth2Error('Jarm Auth Response must be either encrypted, signed, or signed and encrypted.')
  }

  let jarmAuthResponse: JarmAuthResponse | JarmAuthResponseEncryptedOnly

  if (responseIsSigned) {
    const { header: jwsProtectedHeader, payload: jwsPayload } = decodeJwt({
      jwt: decryptedRequestData,
      headerSchema: z.object({ ...zJwtHeader.shape, kid: z.string() }),
    })

    const response = zJarmAuthResponse.parse(jwsPayload)
    const jwtSigner = jwtSignerFromJwt({ header: jwsProtectedHeader, payload: jwsPayload })

    const verificationResult = await options.callbacks.verifyJwt(jwtSigner, {
      compact: decryptedRequestData,
      header: jwsProtectedHeader,
      payload: jwsPayload,
    })

    if (!verificationResult.verified) {
      throw new Oauth2Error('Jarm Auth Response is not valid.')
    }

    jarmAuthResponse = response
  } else {
    const jsonRequestData: unknown = JSON.parse(decryptedRequestData)
    jarmAuthResponse = zJarmAuthResponseEncryptedOnly.parse(jsonRequestData)
  }

  const { authorizationRequest } = await callbacks.getOpenid4vpAuthorizationRequest(jarmAuthResponse)

  jarmAuthResponseValidate({
    clientId: authorizationRequest.client_id,
    authorizationResponse: jarmAuthResponse,
  })
  const type: JarmMode =
    requestDataIsEncrypted && responseIsSigned
      ? JarmMode.SignedEncrypted
      : requestDataIsEncrypted
        ? JarmMode.Encrypted
        : JarmMode.Signed

  const issuer = jarmAuthResponse.iss
  return { authorizationRequest, jarmAuthResponse, type, issuer }
}
