import { type JwtSigner, decodeJwt, jwtHeaderFromJwtSigner } from '@animo-id/oauth2'
import {
  type CredentialRequestJwtProofTypeHeader,
  type CredentialRequestJwtProofTypePayload,
  vCredentialRequestJwtProofTypeHeader,
  vCredentialRequestJwtProofTypePayload,
} from './v-jwt-proof-type'

import { type CallbackContext, jwtSignerFromJwt, verifyJwt } from '@animo-id/oauth2'
import { Oid4vciError } from '../../../error/Oid4vciError'

export interface CreateCredentialRequestJwtProofOptions {
  /**
   * Nonce to use in the jwt. Should be derived from the c_nonce
   */
  nonce?: string

  /**
   * The credential issuer identifier
   */
  credentialIssuer: string

  /**
   * The date when the token was issued. If not provided the current time will be used.
   */
  issuedAt?: Date

  /**
   * The client id of the wallet requesting the credential. Should not be included when using
   * the pre-authorized code flow
   */
  clientId?: string

  signer: JwtSigner

  callbacks: Pick<CallbackContext, 'signJwt'>
}

export async function createCredentialRequestJwtProof(
  options: CreateCredentialRequestJwtProofOptions
): Promise<string> {
  const header: CredentialRequestJwtProofTypeHeader = {
    ...jwtHeaderFromJwtSigner(options.signer),
    typ: 'openid4vci-proof+jwt',
  }

  const payload = {
    nonce: options.nonce,
    aud: options.credentialIssuer,
    iat: Math.floor((options.issuedAt ?? new Date()).getTime() / 1000),
    iss: options.clientId,
  } satisfies CredentialRequestJwtProofTypePayload

  return await options.callbacks.signJwt(options.signer, { header, payload })
}

export interface VerifyCredentialRequestJwtProofOptions {
  /**
   * The proof jwt
   */
  jwt: string

  /**
   * Expected nonce. Should be a c_nonce previously shared with the wallet
   */
  expectedNonce: string

  /**
   * Date at which the nonce will expire
   */
  nonceExpiresAt?: Date

  /**
   * The credential issuer identifier, will be matched against the `aud` claim.
   */
  credentialIssuer: string

  /**
   * The client id of the wallet requesting the credential, if available.
   */
  clientId?: string

  /**
   * Current time, if not provided a new date instance will be created
   */
  now?: Date

  /**
   * Callbacks required for the jwt verification
   */
  callbacks: Pick<CallbackContext, 'verifyJwt'>
}

export async function verifyCredentialRequestJwtProof(options: VerifyCredentialRequestJwtProofOptions) {
  const { header, payload } = decodeJwt({
    jwt: options.jwt,
    headerSchema: vCredentialRequestJwtProofTypeHeader,
    payloadSchema: vCredentialRequestJwtProofTypePayload,
  })

  const now = options.now?.getTime() ?? Date.now()
  if (options.nonceExpiresAt && now > options.nonceExpiresAt.getTime()) {
    throw new Oid4vciError('Nonce used for credential request proof expired')
  }

  const signer = jwtSignerFromJwt({ header, payload })
  await verifyJwt({
    compact: options.jwt,
    header,
    payload,
    signer,
    verifyJwtCallback: options.callbacks.verifyJwt,
    errorMessage: 'Error verifiying credential request proof jwt',
    expectedNonce: options.expectedNonce,
    expectedAudience: options.credentialIssuer,
    expectedIssuer: options.clientId,
    now: options.now,
  })

  return {
    header,
    payload,
    signer,
  }
}
