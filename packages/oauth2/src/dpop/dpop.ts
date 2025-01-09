import { type CallbackContext, HashAlgorithm } from '../callbacks'
import { calculateJwkThumbprint } from '../common/jwk/jwk-thumbprint'
import { decodeJwt } from '../common/jwt/decode-jwt'
import type { JwtSignerJwk } from '../common/jwt/v-jwt'
import { Oauth2Error } from '../error/Oauth2Error'

import {
  type FetchHeaders,
  URL,
  dateToSeconds,
  decodeUtf8String,
  encodeToBase64Url,
  parseWithErrorHandling,
} from '@openid4vc/utils'
import { verifyJwt } from '../common/jwt/verify-jwt'
import type { RequestLike } from '../common/v-common'
import { type DpopJwtHeader, type DpopJwtPayload, vDpopJwtHeader, vDpopJwtPayload } from './v-dpop'

export interface RequestDpopOptions {
  /**
   * Dpop nonce to use for constructing the dpop jwt
   */
  nonce?: string

  /**
   * The signer of the dpop jwt
   */
  signer: JwtSignerJwk
}

export async function createDpopHeadersForRequest(options: CreateDpopJwtOptions) {
  const dpopJwt = await createDpopJwt(options)

  return {
    DPoP: dpopJwt,
  }
}

export interface CreateDpopJwtOptions {
  request: Omit<RequestLike, 'headers'>

  /**
   * Dpop nonce value
   */
  nonce?: string

  /**
   * Creation time of the JWT. If not provided the current date will be used
   */
  issuedAt?: Date

  /**
   * Additional payload to include in the dpop jwt payload. Will be applied after
   * any default claims that are included, so add claims with caution.
   */
  additionalPayload?: Record<string, unknown>

  /**
   * The access token to which the dpop jwt should be bound. Required
   * when the dpop will be sent along with an access token.
   *
   * If provided, the `hashCallback` parameter also needs to be provided
   */
  accessToken?: string

  /**
   * Callback used for dpop
   */
  callbacks: Pick<CallbackContext, 'generateRandom' | 'hash' | 'signJwt'>

  /**
   * The signer of the dpop jwt. Only jwk signer allowed.
   */
  signer: JwtSignerJwk
}

export async function createDpopJwt(options: CreateDpopJwtOptions) {
  // Calculate access token hash
  let ath: string | undefined = undefined
  if (options.accessToken) {
    ath = encodeToBase64Url(await options.callbacks.hash(decodeUtf8String(options.accessToken), HashAlgorithm.Sha256))
  }

  const header = parseWithErrorHandling(vDpopJwtHeader, {
    typ: 'dpop+jwt',
    jwk: options.signer.publicJwk,
    alg: options.signer.alg,
  } satisfies DpopJwtHeader)

  const payload = parseWithErrorHandling(vDpopJwtPayload, {
    htu: htuFromRequestUrl(options.request.url),
    iat: dateToSeconds(options.issuedAt),
    htm: options.request.method,
    jti: encodeToBase64Url(await options.callbacks.generateRandom(32)),
    ath,
    nonce: options.nonce,
    ...options.additionalPayload,
  } satisfies DpopJwtPayload)

  const { jwt } = await options.callbacks.signJwt(options.signer, {
    header,
    payload,
  })

  return jwt
}

export interface VerifyDpopJwtOptions {
  /**
   * The compact dpop jwt.
   */
  dpopJwt: string

  /**
   * The requet for which to verify the dpop jwt
   */
  request: RequestLike

  /**
   * Allowed dpop signing alg values. If not provided
   * any alg values are allowed and it's up to the `verifyJwtCallback`
   * to handle the alg.
   */
  allowedSigningAlgs?: string[]

  /**
   * Expected nonce in the payload. If not provided the nonce won't be validated.
   */
  expectedNonce?: string

  /**
   * Access token to which the dpop jwt is bound. If provided the sha-256 hash of the
   * access token needs to match the 'ath' claim.
   */
  accessToken?: string

  /**
   * The expected jwk thumprint 'jti' confirmation method. If provided the thumprint of the
   * jwk used to sign the dpop jwt must match this provided thumbprint value. The 'jti' value
   * can be extracted from the access token payload, or if opaque tokens are used can be retrieved
   * using token introspection.
   */
  expectedJwkThumbprint?: string

  /**
   * Callbacks used for verifying dpop jwt
   */
  callbacks: Pick<CallbackContext, 'verifyJwt' | 'hash'>

  now?: Date
}

export async function verifyDpopJwt(options: VerifyDpopJwtOptions) {
  const { header, payload } = decodeJwt({
    jwt: options.dpopJwt,
    headerSchema: vDpopJwtHeader,
    payloadSchema: vDpopJwtPayload,
  })

  if (options.allowedSigningAlgs && !options.allowedSigningAlgs.includes(header.alg)) {
    throw new Oauth2Error(
      `dpop jwt uses alg value '${header.alg}' but allowed dpop signging alg values are ${options.allowedSigningAlgs.join(', ')}.`
    )
  }

  if (options.expectedNonce) {
    if (!payload.nonce) {
      throw new Oauth2Error(`Dpop jwt does not have a nonce value, but expected nonce value '${options.expectedNonce}'`)
    }

    if (payload.nonce !== options.expectedNonce) {
      throw new Oauth2Error(
        `Dpop jwt contains nonce value '${payload.nonce}', but expected nonce value '${options.expectedNonce}'`
      )
    }
  }

  if (options.request.method !== payload.htm) {
    throw new Oauth2Error(
      `Dpop jwt contains htm value '${payload.htm}', but expected htm value '${options.request.method}'`
    )
  }

  const expectedHtu = htuFromRequestUrl(options.request.url)
  if (expectedHtu !== payload.htu) {
    throw new Oauth2Error(`Dpop jwt contains htu value '${payload.htu}', but expected htu value '${expectedHtu}'.`)
  }

  if (options.accessToken) {
    const expectedAth = encodeToBase64Url(
      await options.callbacks.hash(decodeUtf8String(options.accessToken), HashAlgorithm.Sha256)
    )

    if (!payload.ath) {
      throw new Oauth2Error(`Dpop jwt does not have a ath value, but expected ath value '${expectedAth}'.`)
    }

    if (payload.ath !== expectedAth) {
      throw new Oauth2Error(`Dpop jwt contains ath value '${payload.ath}', but expected ath value '${expectedAth}'.`)
    }
  }

  if (options.expectedJwkThumbprint) {
    const jwkThumprint = await calculateJwkThumbprint({
      hashAlgorithm: HashAlgorithm.Sha256,
      hashCallback: options.callbacks.hash,
      jwk: header.jwk,
    })

    if (options.expectedJwkThumbprint !== jwkThumprint) {
      throw new Oauth2Error(
        `Dpop is signed with jwk with thumbprint value '${jwkThumprint}', but expect jwk thumbprint value '${options.expectedJwkThumbprint}'`
      )
    }
  }

  await verifyJwt({
    signer: {
      alg: header.alg,
      method: 'jwk',
      publicJwk: header.jwk,
    },
    now: options.now,
    header,
    payload,
    compact: options.dpopJwt,
    verifyJwtCallback: options.callbacks.verifyJwt,
    errorMessage: 'dpop jwt verification failed',
  })

  return {
    header,
    payload,
  }
}

function htuFromRequestUrl(requestUrl: string) {
  const htu = new URL(requestUrl)
  htu.search = ''
  htu.hash = ''

  return htu.toString()
}

export function extractDpopNonceFromHeaders(headers: FetchHeaders) {
  return headers.get('DPoP-Nonce')
}

export function extractDpopJwtFromHeaders(headers: FetchHeaders): { valid: true; dpopJwt?: string } | { valid: false } {
  const dpopJwt = headers.get('DPoP')

  if (dpopJwt && (typeof dpopJwt !== 'string' || dpopJwt.includes(','))) {
    return { valid: false }
  }

  return { valid: true, dpopJwt: dpopJwt ?? undefined }
}
