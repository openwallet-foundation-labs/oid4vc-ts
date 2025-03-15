import {
  type CallbackContext,
  type JweEncryptor,
  type JwtSigner,
  Oauth2Error,
  jwtHeaderFromJwtSigner,
} from '@openid4vc/oauth2'
import type {
  JarmAuthorizationResponse,
  JarmAuthorizationResponseEncryptedOnly,
} from './jarm-authorization-response/z-jarm-authorization-response'

export interface CreateJarmAuthorizationResponseOptions {
  jarmAuthorizationResponse: JarmAuthorizationResponse | JarmAuthorizationResponseEncryptedOnly
  jwtSigner?: JwtSigner
  jweEncryptor?: JweEncryptor
  callbacks: Pick<CallbackContext, 'signJwt' | 'encryptJwe'>
}

export async function createJarmAuthorizationResponse(options: CreateJarmAuthorizationResponseOptions) {
  const { jarmAuthorizationResponse, jweEncryptor, jwtSigner, callbacks } = options
  if (!jwtSigner && jweEncryptor) {
    const { jwe } = await callbacks.encryptJwe(jweEncryptor, JSON.stringify(jarmAuthorizationResponse))
    return { jarmAuthorizationResponseJwt: jwe }
  }

  if (jwtSigner && !jweEncryptor) {
    const signed = await callbacks.signJwt(jwtSigner, {
      header: jwtHeaderFromJwtSigner(jwtSigner),
      payload: jarmAuthorizationResponse,
    })
    return { jarmAuthorizationResponseJwt: signed.jwt }
  }

  if (!jwtSigner || !jweEncryptor) {
    throw new Oauth2Error('JWT signer and/or encryptor are required to create a JARM auth response.')
  }
  const signed = await callbacks.signJwt(jwtSigner, {
    header: jwtHeaderFromJwtSigner(jwtSigner),
    payload: jarmAuthorizationResponse,
  })

  const encrypted = await callbacks.encryptJwe(jweEncryptor, signed.jwt)

  return { jarmAuthorizationResponseJwt: encrypted.jwe }
}
