import * as v from 'valibot'

import {
  type CallbackContext,
  Oauth2Error,
  decodeJwt,
  decodeJwtHeader,
  jwtSignerFromJwt,
  vCompactJwe,
  vCompactJwt,
} from '@openid4vc/oauth2'
import { jarmAuthResponseValidate } from './jarm-validate-auth-response'
import {
  type JarmAuthResponse,
  type JarmAuthResponseEncryptedOnly,
  vJarmAuthResponse,
  vJarmAuthResponseEncryptedOnly,
} from './v-jarm-auth-response'

/**
 * The client decrypts the JWT using the default key for the respective issuer or,
 * if applicable, determined by the kid JWT header parameter.
 * The key might be a private key, where the corresponding public key is registered
 * with the expected issuer of the response ("use":"enc" via the client's metadata jwks or jwks_uri)
 * or a key derived from its client secret (see Section 2.2).
 */
const decryptJarmRequestData = async (options: {
  requestData: string
  callbacks: Pick<CallbackContext, 'decryptJwt'>
}) => {
  const { requestData, callbacks } = options

  const { header } = decodeJwtHeader({ jwe: requestData })
  if (!header.kid) {
    throw new Oauth2Error('Jarm JWE is missing the protected header field "kid".')
  }

  const result = await callbacks.decryptJwt(requestData)
  if (!result.decrypted) {
    throw new Oauth2Error('Failed to decrypt jarm auth response.')
  }

  return result.payload
}

/**
 * Validate a JARM direct_post.jwt compliant authentication response
 * * The decryption key should be resolvable using the the protected header's 'kid' field
 * * The signature verification jwk should be resolvable using the jws protected header's 'kid' field and the payload's 'iss' field.
 */
export async function verifyJarmAuthResponse(options: {
  jarmAuthResponseJwt: string
  getAuthRequest: (
    authResponse: JarmAuthResponse | JarmAuthResponseEncryptedOnly
  ) => Promise<{ authRequest: { client_id: string; nonce: string; state?: string } }>
  callbacks: Pick<CallbackContext, 'decryptJwt' | 'verifyJwt'>
}) {
  const { jarmAuthResponseJwt } = options

  const requestDataIsEncrypted = v.is(vCompactJwe, jarmAuthResponseJwt)
  const decryptedRequestData = requestDataIsEncrypted
    ? await decryptJarmRequestData({ requestData: jarmAuthResponseJwt, callbacks: options.callbacks })
    : jarmAuthResponseJwt

  const responseIsSigned = v.is(vCompactJwt, decryptedRequestData)
  if (!requestDataIsEncrypted && !responseIsSigned) {
    throw new Oauth2Error('Jarm Auth Response must be either encrypted, signed, or signed and encrypted.')
  }

  let jarmAuthResponse: JarmAuthResponse | JarmAuthResponseEncryptedOnly

  if (responseIsSigned) {
    const { header: jwsProtectedHeader, payload: jwsPayload } = decodeJwt({
      jwt: decryptedRequestData,
    })

    const response = v.parse(vJarmAuthResponse, jwsPayload)

    if (!jwsProtectedHeader.kid) {
      throw new Oauth2Error('Jarm JWS is missing the protected header field "kid".')
    }

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
    jarmAuthResponse = v.parse(vJarmAuthResponseEncryptedOnly, jsonRequestData)
  }

  const { authRequest } = await options.getAuthRequest(jarmAuthResponse)

  jarmAuthResponseValidate({ authRequest, authResponse: jarmAuthResponse })

  let type: 'signed encrypted' | 'encrypted' | 'signed'
  if (responseIsSigned && requestDataIsEncrypted) {
    type = 'signed encrypted'
  } else if (requestDataIsEncrypted) {
    type = 'encrypted'
  } else {
    type = 'signed'
  }

  const issuer = jarmAuthResponse.iss
  return { authRequest, jarmAuthResponse, type, issuer }
}
