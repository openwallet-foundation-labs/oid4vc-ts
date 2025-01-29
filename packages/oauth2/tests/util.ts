import crypto from 'node:crypto'
import { decodeBase64, encodeToUtf8String } from '@openid4vc/utils'
import * as jose from 'jose'
import { type CallbackContext, HashAlgorithm, type SignJwtCallback } from '../src/callbacks'
import { clientAuthenticationNone } from '../src/client-authentication'
import { calculateJwkThumbprint } from '../src/common/jwk/jwk-thumbprint'
import type { Jwk } from '../src/common/jwk/v-jwk'

export function parseXwwwFormUrlEncoded(text: string) {
  return Object.fromEntries(Array.from(new URLSearchParams(text).entries()))
}

export const callbacks = {
  hash: (data, alg) => crypto.createHash(alg.replace('-', '').toLowerCase()).update(data).digest(),
  generateRandom: (bytes) => crypto.randomBytes(bytes),
  clientAuthentication: clientAuthenticationNone(),
  verifyJwt: async (signer, { compact, payload }) => {
    let jwk: Jwk
    if (signer.method === 'did') {
      jwk = JSON.parse(encodeToUtf8String(decodeBase64(signer.didUrl.split('#')[0].replace('did:jwk:', ''))))
    } else if (signer.method === 'jwk') {
      jwk = signer.publicJwk
    } else {
      throw new Error('Signer method not supported')
    }

    const josePublicKey = await jose.importJWK(jwk as jose.JWK, signer.alg)
    try {
      await jose.jwtVerify(compact, josePublicKey, {
        currentDate: payload.exp ? new Date((payload.exp - 300) * 1000) : undefined,
      })
      return {
        verified: true,
        signerJwk: jwk,
      }
    } catch (error) {
      return {
        verified: false,
      }
    }
  },
} as const satisfies Partial<CallbackContext>

export const getSignJwtCallback = (privateJwks: Jwk[]): SignJwtCallback => {
  return async (signer, { header, payload }) => {
    let jwk: Jwk
    if (signer.method === 'did') {
      jwk = JSON.parse(encodeToUtf8String(decodeBase64(signer.didUrl.split('#')[0].replace('did:jwk:', ''))))
    } else if (signer.method === 'jwk') {
      jwk = signer.publicJwk
    } else {
      throw new Error('Signer method not supported')
    }

    const jwkThumprint = await calculateJwkThumbprint({
      jwk,
      hashAlgorithm: HashAlgorithm.Sha256,
      hashCallback: callbacks.hash,
    })

    const privateJwk = await Promise.all(
      privateJwks.map(async (jwk) =>
        (await calculateJwkThumbprint({
          hashAlgorithm: HashAlgorithm.Sha256,
          hashCallback: callbacks.hash,
          jwk,
        })) === jwkThumprint
          ? jwk
          : undefined
      )
    ).then((jwks) => jwks.find((jwk) => jwk !== undefined))

    if (!privateJwk) {
      throw new Error(`No private key available for public jwk \n${JSON.stringify(jwk, null, 2)}`)
    }

    const josePrivateKey = await jose.importJWK(privateJwk as jose.JWK, signer.alg)
    const jwt = await new jose.SignJWT(payload).setProtectedHeader(header).sign(josePrivateKey)

    return {
      jwt: jwt,
      signerJwk: jwk,
    }
  }
}
