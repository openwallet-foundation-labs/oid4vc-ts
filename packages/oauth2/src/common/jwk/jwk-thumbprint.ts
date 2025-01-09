import * as v from 'valibot'
import type { HashAlgorithm, HashCallback } from '../../callbacks'

import { decodeUtf8String, encodeToBase64Url, parseWithErrorHandling } from '@openid4vc/utils'
import type { Jwk } from './v-jwk'

const vJwkThumbprintComponents = v.variant('kty', [
  v.pipe(
    v.looseObject({
      kty: v.literal('EC'),
      crv: v.string(),
      x: v.string(),
      y: v.string(),
    }),
    v.transform(({ crv, kty, x, y }) => ({ crv, kty, x, y }))
  ),
  v.pipe(
    v.looseObject({
      kty: v.literal('OKP'),
      crv: v.string(),
      x: v.string(),
    }),
    v.transform(({ crv, kty, x }) => ({ crv, kty, x }))
  ),
  v.pipe(
    v.looseObject({
      kty: v.literal('RSA'),
      e: v.string(),
      n: v.string(),
    }),
    v.transform(({ e, kty, n }) => ({ e, kty, n }))
  ),
  v.pipe(
    v.looseObject({
      kty: v.literal('oct'),
      k: v.string(),
    }),
    v.transform(({ k, kty }) => ({ k, kty }))
  ),
])

export interface CalculateJwkThumbprintOptions {
  /**
   * The jwk to calcualte the thumbprint for.
   */
  jwk: Jwk

  /**
   * The hashing algorithm to use for calculating the thumbprint
   */
  hashAlgorithm: HashAlgorithm

  /**
   * The hash callback to calculate the digest
   */
  hashCallback: HashCallback
}

export async function calculateJwkThumbprint(options: CalculateJwkThumbprintOptions): Promise<string> {
  const jwkThumbprintComponents = parseWithErrorHandling(
    vJwkThumbprintComponents,
    options.jwk,
    `Provided jwk does not match a supported jwk structure. Either the 'kty' is not supported, or required values are missing.`
  )

  const thumbprint = encodeToBase64Url(
    await options.hashCallback(decodeUtf8String(JSON.stringify(jwkThumbprintComponents)), options.hashAlgorithm)
  )
  return thumbprint
}
