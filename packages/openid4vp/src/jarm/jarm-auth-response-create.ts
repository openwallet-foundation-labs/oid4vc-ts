import {
  type CallbackContext,
  type JweEncryptor,
  type JwtSigner,
  Oauth2Error,
  jwtHeaderFromJwtSigner,
} from '@openid4vc/oauth2'
import type { JarmAuthResponse, JarmAuthResponseEncryptedOnly } from './jarm-auth-response/z-jarm-auth-response'

export interface CreateJarmAuthResponseOptions {
  jarmAuthResponse: JarmAuthResponse | JarmAuthResponseEncryptedOnly
  jwtSigner?: JwtSigner
  jwtEncryptor?: JweEncryptor
  callbacks: Pick<CallbackContext, 'signJwt' | 'encryptJwe'>
}

export async function createJarmAuthResponse(input: CreateJarmAuthResponseOptions) {
  const { jarmAuthResponse, jwtEncryptor, jwtSigner, callbacks } = input
  if (!jwtSigner && jwtEncryptor) {
    const { jwe } = await callbacks.encryptJwe(jwtEncryptor, JSON.stringify(jarmAuthResponse))
    return { jarmAuthResponseJwt: jwe }
  }

  if (jwtSigner && !jwtEncryptor) {
    const signed = await callbacks.signJwt(jwtSigner, {
      header: jwtHeaderFromJwtSigner(jwtSigner),
      payload: jarmAuthResponse,
    })
    return { jarmAuthResponseJwt: signed.jwt }
  }

  if (!jwtSigner || !jwtEncryptor) {
    throw new Oauth2Error('JWT signer and/or encryptor are required to create a JARM auth response.')
  }
  const signed = await callbacks.signJwt(jwtSigner, {
    header: jwtHeaderFromJwtSigner(jwtSigner),
    payload: jarmAuthResponse,
  })

  const encrypted = await callbacks.encryptJwe(jwtEncryptor, signed.jwt)

  return { jarmAuthResponseJwt: encrypted.jwe }
}
