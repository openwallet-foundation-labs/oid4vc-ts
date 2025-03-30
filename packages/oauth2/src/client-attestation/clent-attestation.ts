import { type FetchHeaders, dateToSeconds, parseWithErrorHandling } from '@openid4vc/utils'
import type { CallbackContext } from '../callbacks'
import { decodeJwt, jwtHeaderFromJwtSigner, jwtSignerFromJwt } from '../common/jwt/decode-jwt'
import { verifyJwt } from '../common/jwt/verify-jwt'
import { type JwtSigner, zCompactJwt } from '../common/jwt/z-jwt'
import { Oauth2ErrorCodes } from '../common/z-oauth2-error'
import { Oauth2Error } from '../error/Oauth2Error'
import { Oauth2ServerErrorResponseError } from '../error/Oauth2ServerErrorResponseError'
import { verifyClientAttestationPopJwt } from './client-attestation-pop'
import {
  type ClientAttestationJwtHeader,
  type ClientAttestationJwtPayload,
  oauthClientAttestationHeader,
  oauthClientAttestationPopHeader,
  zClientAttestationJwtHeader,
  zClientAttestationJwtPayload,
} from './z-client-attestation'

export interface VerifyClientAttestationJwtOptions {
  /**
   * The compact client attestation jwt.
   */
  clientAttestationJwt: string

  /**
   * Date to use for expiration. If not provided current date will be used.
   */
  now?: Date

  /**
   * Callbacks used for verifying client attestation pop jwt.
   */
  callbacks: Pick<CallbackContext, 'verifyJwt'>

  // TODO: expectedClientId? expectedIssuer?
}

export type VerifiedClientAttestationJwt = Awaited<ReturnType<typeof verifyClientAttestationJwt>>
export async function verifyClientAttestationJwt(options: VerifyClientAttestationJwtOptions) {
  const { header, payload } = decodeJwt({
    jwt: options.clientAttestationJwt,
    headerSchema: zClientAttestationJwtHeader,
    payloadSchema: zClientAttestationJwtPayload,
  })

  const { signer } = await verifyJwt({
    signer: jwtSignerFromJwt({ header, payload }),
    now: options.now,
    header,
    payload,
    compact: options.clientAttestationJwt,
    verifyJwtCallback: options.callbacks.verifyJwt,
    errorMessage: 'client attestation jwt verification failed.',
  })

  return {
    header,
    payload,
    signer,
  }
}

export interface CreateClientAttestationJwtOptions {
  /**
   * Creation time of the JWT. If not provided the current date will be used
   */
  issuedAt?: Date

  /**
   * Expiration time of the JWT.
   */
  expiresAt: Date

  /**
   * Issuer of the client attestation, usually identifier of the client backend
   */
  issuer: string

  /**
   * The client id of the client instance.
   */
  clientId: string

  /**
   * The confirmation payload for the client, attesting the `jwk`, `key_type` and `user_authentication`
   */
  confirmation: ClientAttestationJwtPayload['cnf']

  /**
   * Additional payload to include in the client attestation jwt payload. Will be applied after
   * any default claims that are included, so add claims with caution.
   */
  additionalPayload?: Record<string, unknown>

  /**
   * Callback used for client attestation
   */
  callbacks: Pick<CallbackContext, 'signJwt'>

  /**
   * The signer of the client attestation jwt.
   */
  signer: JwtSigner
}

export async function createClientAttestationJwt(options: CreateClientAttestationJwtOptions) {
  const header = parseWithErrorHandling(zClientAttestationJwtHeader, {
    typ: 'oauth-client-attestation+jwt',
    ...jwtHeaderFromJwtSigner(options.signer),
  } satisfies ClientAttestationJwtHeader)

  const payload = parseWithErrorHandling(zClientAttestationJwtPayload, {
    iss: options.issuer,
    iat: dateToSeconds(options.issuedAt),
    exp: dateToSeconds(options.expiresAt),
    sub: options.clientId,
    cnf: options.confirmation,
    ...options.additionalPayload,
  } satisfies ClientAttestationJwtPayload)

  const { jwt } = await options.callbacks.signJwt(options.signer, {
    header,
    payload,
  })

  return jwt
}

export function extractClientAttestationJwtsFromHeaders(
  headers: FetchHeaders
):
  | { valid: false }
  | { valid: true; clientAttestationHeader?: undefined; clientAttestationPopHeader?: undefined }
  | { valid: true; clientAttestationHeader: string; clientAttestationPopHeader: string } {
  const clientAttestationHeader = headers.get(oauthClientAttestationHeader)
  const clientAttestationPopHeader = headers.get(oauthClientAttestationPopHeader)

  if (!clientAttestationHeader && !clientAttestationPopHeader) {
    return { valid: true }
  }

  if (!clientAttestationHeader || !clientAttestationPopHeader) {
    return { valid: false }
  }

  if (
    !zCompactJwt.safeParse(clientAttestationHeader).success ||
    !zCompactJwt.safeParse(clientAttestationPopHeader).success
  ) {
    return { valid: false } as const
  }

  return {
    valid: true,
    clientAttestationPopHeader,
    clientAttestationHeader,
  } as const
}

export interface VerifyClientAttestationOptions {
  authorizationServer: string
  clientAttestationJwt: string
  clientAttestationPopJwt: string
  callbacks: Pick<CallbackContext, 'verifyJwt'>

  /**
   * Date to use for expiration. If not provided current date will be used.
   */
  now?: Date
}

export async function verifyClientAttestation({
  authorizationServer,
  clientAttestationJwt,
  clientAttestationPopJwt,
  callbacks,
  now,
}: VerifyClientAttestationOptions) {
  try {
    const clientAttestation = await verifyClientAttestationJwt({
      callbacks,
      clientAttestationJwt,
      now,
    })

    const clientAttestationPop = await verifyClientAttestationPopJwt({
      callbacks: callbacks,
      authorizationServer,
      clientAttestation,
      clientAttestationPopJwt,
      now,
    })

    return {
      clientAttestation,
      clientAttestationPop,
    }
  } catch (error) {
    if (error instanceof Oauth2Error) {
      throw new Oauth2ServerErrorResponseError(
        {
          error: Oauth2ErrorCodes.InvalidClient,
          error_description: `Error verifying client attestation. ${error.message}`,
        },
        {
          status: 401,
          cause: error,
        }
      )
    }

    throw new Oauth2ServerErrorResponseError(
      {
        error: Oauth2ErrorCodes.ServerError,
        error_description: 'Error during verification of client attestation jwt',
      },
      {
        status: 500,
        cause: error,
        internalMessage: 'Unknown error thrown during verification of client attestation jwt',
      }
    )
  }
}
