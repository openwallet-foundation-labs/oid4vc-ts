import crypto, { webcrypto } from 'node:crypto'
import { decodeBase64, encodeToUtf8String } from '@openid4vc/utils'
import * as jose from 'jose'
import { type CallbackContext, HashAlgorithm, type SignJwtCallback, type VerifyJwtCallback } from '../src/callbacks'
import { clientAuthenticationNone } from '../src/client-authentication'
import { calculateJwkThumbprint } from '../src/common/jwk/jwk-thumbprint'
import type { Jwk } from '../src/common/jwk/z-jwk'

// Needed for Node 18 support with jose6. We can soon drop node18 support.
if (process.versions.node.startsWith('18.')) {
  // @ts-expect-error
  globalThis.crypto = webcrypto
}

export function parseXwwwFormUrlEncoded(text: string) {
  return Object.fromEntries(Array.from(new URLSearchParams(text).entries()))
}

export function getVerifyJwtCallback({ publicJwks }: { publicJwks?: Jwk[] } = {}): VerifyJwtCallback {
  return async (signer, { compact, payload }) => {
    let jwk: Jwk
    if (signer.method === 'did') {
      jwk = JSON.parse(encodeToUtf8String(decodeBase64(signer.didUrl.split('#')[0].replace('did:jwk:', ''))))
    } else if (signer.method === 'jwk') {
      jwk = signer.publicJwk
    } else if (signer.method === 'federation') {
      const _jwk = publicJwks?.find((jwk) => jwk.kid === signer.kid)
      if (!_jwk) throw new Error(`No public jwk found for kid ${signer.kid}`)
      jwk = _jwk
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
    } catch (_error) {
      return {
        verified: false,
      }
    }
  }
}

export const callbacks = {
  hash: (data, alg) => crypto.createHash(alg.replace('-', '').toLowerCase()).update(data).digest(),
  generateRandom: (bytes) => crypto.randomBytes(bytes),
  clientAuthentication: clientAuthenticationNone({
    clientId: 'some-random-client-id',
  }),
  verifyJwt: getVerifyJwtCallback(),
  encryptJwe: async (encryptor, payload) => {
    const josePublicKey = await jose.importJWK(encryptor.publicJwk as jose.JWK, encryptor.alg)
    const jwe = await new jose.CompactEncrypt(new TextEncoder().encode(payload))
      .setProtectedHeader({ alg: encryptor.alg, enc: encryptor.enc })
      .encrypt(josePublicKey)
    return { jwe, encryptionJwk: encryptor.publicJwk }
  },
  decryptJwe: async (_jwe) => {
    // Note: In real usage, you'd need the private key to decrypt.
    // This is a placeholder that always returns decrypted: false for tests.
    return { decrypted: false as const }
  },
} as const satisfies Partial<CallbackContext>

export const getSignJwtCallback = (privateJwks: Jwk[]): SignJwtCallback => {
  return async (signer, { header, payload }) => {
    let jwk: Jwk
    if (signer.method === 'did') {
      jwk = JSON.parse(encodeToUtf8String(decodeBase64(signer.didUrl.split('#')[0].replace('did:jwk:', ''))))
    } else if (signer.method === 'federation') {
      const _jwk = privateJwks.find((jwk) => jwk.kid === signer.kid)
      if (!_jwk) throw new Error(`No private jwk found for kid ${signer.kid}`)
      const { d, ...publicJwk } = _jwk
      jwk = publicJwk
    } else if (signer.method === 'jwk') {
      jwk = signer.publicJwk
    } else {
      throw new Error('Signer method not supported')
    }

    const jwkThumbprint = await calculateJwkThumbprint({
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
        })) === jwkThumbprint
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
