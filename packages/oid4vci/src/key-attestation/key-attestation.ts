import { type Jwk, type JwtSigner, decodeJwt, jwtHeaderFromJwtSigner } from '@openid4vc/oauth2'

import { type CallbackContext, jwtSignerFromJwt, verifyJwt } from '@openid4vc/oauth2'
import { type StringWithAutoCompletion, dateToSeconds, parseWithErrorHandling } from '@openid4vc/utils'
import { Oid4vciError } from '../error/Oid4vciError'
import {
  type Iso18045,
  type KeyAttestationJwtHeader,
  type KeyAttestationJwtPayload,
  type KeyAttestationJwtUse,
  vKeyAttestationJwtHeader,
  vKeyAttestationJwtPayloadForUse,
} from './v-key-attestation'

export interface CreateKeyAttestationJwtOptions {
  /**
   * Nonce to use in the key attestation.
   *
   * MUST be present if the attestation is used with the attestation proof
   */
  nonce?: string

  /**
   * The date when the key attestation was issued. If not provided the current time will be used.
   */
  issuedAt?: Date

  /**
   * The date when the key attestation will expire.
   *
   * MUST be present if the attestation is used with the JWT proof
   */
  expiresAt?: Date

  /**
   * The keys that the attestation jwt attests.
   */
  attestedKeys: Jwk[]

  /**
   * Optional attack potential resistance of attested keys and key storage
   */
  keyStorage?: StringWithAutoCompletion<Iso18045>[]

  /**
   * Optional attack potential resistance of user authentication methods
   */
  userAuthentication?: StringWithAutoCompletion<Iso18045>[]

  /**
   * Optional url linking to the certification of the key storage component.
   */
  certification?: string

  /**
   * The intended use of the key attestation. Based on this additional validation
   * is performed.
   *
   * - `proof_type.jwt` -> `exp` MUST be set
   * - `proof_type.attestation` -> `nonce` MUST be set
   */
  use?: KeyAttestationJwtUse

  /**
   * Signer of the key attestation jwt
   */
  signer: JwtSigner

  /**
   * Callbacks used for creating the key attestation jwt
   */
  callbacks: Pick<CallbackContext, 'signJwt'>

  /**
   * Additional payload to include in the key attestation jwt payload. Will be applied after
   * any default claims that are included, so add claims with caution.
   */
  additionalPayload?: Record<string, unknown>
}

export async function createKeyAttestationJwt(options: CreateKeyAttestationJwtOptions): Promise<string> {
  const header = parseWithErrorHandling(vKeyAttestationJwtHeader, {
    ...jwtHeaderFromJwtSigner(options.signer),
    typ: 'keyattestation+jwt',
  } satisfies KeyAttestationJwtHeader)

  const payload = parseWithErrorHandling(vKeyAttestationJwtPayloadForUse(options.use), {
    iat: dateToSeconds(options.issuedAt),
    exp: options.expiresAt ? dateToSeconds(options.expiresAt) : undefined,
    nonce: options.nonce,
    attested_keys: options.attestedKeys,
    user_authentication: options.userAuthentication,
    key_storage: options.keyStorage,
    certification: options.certification,
    ...options.additionalPayload,
  } satisfies KeyAttestationJwtPayload)

  const { jwt } = await options.callbacks.signJwt(options.signer, { header, payload })
  return jwt
}

export interface VerifyKeyAttestationJwtOptions {
  /**
   * The compact key attestation jwt
   */
  keyAttestationJwt: string

  /**
   * Expected nonce. If the key attestation is used directly as proof this should be provided.
   */
  expectedNonce?: string

  /**
   * Date at which the nonce will expire
   */
  nonceExpiresAt?: Date

  /**
   * The intended use of the key attestation. Based on this additional validation
   * is performed.
   *
   * - `proof_type.jwt` -> `exp` MUST be set
   * - `proof_type.attestation` -> `nonce` MUST be set
   */
  use?: KeyAttestationJwtUse

  /**
   * Current time, if not provided a new date instance will be created
   */
  now?: Date

  /**
   * Callbacks required for the key attestation jwt verification
   */
  callbacks: Pick<CallbackContext, 'verifyJwt'>
}

export type VerifyKeyAttestationJwtReturn = Awaited<ReturnType<typeof verifyKeyAttestationJwt>>
export async function verifyKeyAttestationJwt(options: VerifyKeyAttestationJwtOptions) {
  const { header, payload } = decodeJwt({
    jwt: options.keyAttestationJwt,
    headerSchema: vKeyAttestationJwtHeader,
    payloadSchema: vKeyAttestationJwtPayloadForUse(options.use),
  })

  // TODO: if you use stateless nonce, it doesn't make sense to verify the nonce here
  // We should just return the nonce after verification so it can be checked (or actually, it should be checked upfront)
  const now = options.now?.getTime() ?? Date.now()
  if (options.nonceExpiresAt && now > options.nonceExpiresAt.getTime()) {
    throw new Oid4vciError('Nonce used for key attestation jwt expired')
  }

  const { signer } = await verifyJwt({
    compact: options.keyAttestationJwt,
    header,
    payload,
    signer: jwtSignerFromJwt({ header, payload }),
    verifyJwtCallback: options.callbacks.verifyJwt,
    errorMessage: 'Error verifiying key attestation jwt',
    expectedNonce: options.expectedNonce,
    now: options.now,
  })

  return {
    header,
    payload,
    signer,
  }
}
