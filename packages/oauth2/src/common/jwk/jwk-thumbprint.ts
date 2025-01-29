import type { HashAlgorithm, HashCallback } from '../../callbacks'

import { decodeUtf8String, encodeToBase64Url, parseWithErrorHandling } from '@openid4vc/utils'
import type { Jwk } from './v-jwk'
import z from 'zod'

export const vJwkThumbprintComponents = z.discriminatedUnion('kty', [
  z.object({
    kty: z.literal('EC'),
    crv: z.string(),
    x: z.string(),
    y: z.string(),
  }),
  z.object({
    kty: z.literal('OKP'),
    crv: z.string(),
    x: z.string(),
  }),
  z.object({
    kty: z.literal('RSA'),
    e: z.string(),
    n: z.string(),
  }),
  z.object({
    kty: z.literal('oct'),
    k: z.string(),
  }),
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
