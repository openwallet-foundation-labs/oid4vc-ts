import { type JwtSigner, decodeJwt, isJwkInSet, jwtHeaderFromJwtSigner } from '@openid4vc/oauth2'
import {
  type CredentialRequestJwtProofTypeHeader,
  type CredentialRequestJwtProofTypePayload,
  zCredentialRequestJwtProofTypeHeader,
  zCredentialRequestJwtProofTypePayload,
} from './z-jwt-proof-type'

import { type CallbackContext, jwtSignerFromJwt, verifyJwt } from '@openid4vc/oauth2'
import { dateToSeconds, parseWithErrorHandling } from '@openid4vc/utils'
import { Oid4vciError } from '../../../error/Oid4vciError'
import { type VerifyKeyAttestationJwtReturn, verifyKeyAttestationJwt } from '../../../key-attestation/key-attestation'
import { zKeyAttestationJwtHeader, zKeyAttestationJwtPayload } from '../../../key-attestation/z-key-attestation'

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

  /**
   * Key attestation jwt that the proof should based on. In this case it is required that the `signer` uses
   * a key from the `attested_keys` in the key attestation jwt payload.
   */
  keyAttestationJwt?: string

  signer: JwtSigner
  callbacks: Pick<CallbackContext, 'signJwt' | 'hash'>
}

export async function createCredentialRequestJwtProof(
  options: CreateCredentialRequestJwtProofOptions
): Promise<string> {
  const header = parseWithErrorHandling(zCredentialRequestJwtProofTypeHeader, {
    ...jwtHeaderFromJwtSigner(options.signer),
    key_attestation: options.keyAttestationJwt,
    typ: 'openid4vci-proof+jwt',
  } satisfies CredentialRequestJwtProofTypeHeader)

  const payload = parseWithErrorHandling(zCredentialRequestJwtProofTypePayload, {
    nonce: options.nonce,
    aud: options.credentialIssuer,
    iat: dateToSeconds(options.issuedAt),
    iss: options.clientId,
  } satisfies CredentialRequestJwtProofTypePayload)

  const { jwt, signerJwk } = await options.callbacks.signJwt(options.signer, { header, payload })

  // Check the jwt is signed with an key from attested_keys in the key_attestation jwt
  if (options.keyAttestationJwt) {
    const decodedKeyAttestation = decodeJwt({
      jwt: options.keyAttestationJwt,
      headerSchema: zKeyAttestationJwtHeader,
      payloadSchema: zKeyAttestationJwtPayload,
    })

    const isSigedWithAttestedKey = await isJwkInSet({
      jwk: signerJwk,
      jwks: decodedKeyAttestation.payload.attested_keys,
      callbacks: options.callbacks,
    })

    if (!isSigedWithAttestedKey) {
      throw new Oid4vciError(
        `Credential request jwt proof is not signed with a key in the 'key_attestation' jwt payload 'attested_keys'`
      )
    }
  }

  return jwt
}

export interface VerifyCredentialRequestJwtProofOptions {
  /**
   * The proof jwt
   */
  jwt: string

  /**
   * Expected nonce. Should be a c_nonce previously shared with the wallet
   */
  expectedNonce?: string

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
   * Callbacks required for the jwt verification.
   *
   * Will be used for the jwt proof, and optionally a `key_attestation` in the jwt proof header.
   */
  callbacks: Pick<CallbackContext, 'verifyJwt' | 'hash'>
}

export async function verifyCredentialRequestJwtProof(options: VerifyCredentialRequestJwtProofOptions) {
  const { header, payload } = decodeJwt({
    jwt: options.jwt,
    headerSchema: zCredentialRequestJwtProofTypeHeader,
    payloadSchema: zCredentialRequestJwtProofTypePayload,
  })

  const now = options.now?.getTime() ?? Date.now()
  if (options.nonceExpiresAt && now > options.nonceExpiresAt.getTime()) {
    throw new Oid4vciError('Nonce used for credential request proof expired')
  }

  const { signer } = await verifyJwt({
    compact: options.jwt,
    header,
    payload,
    signer: jwtSignerFromJwt({ header, payload }),
    verifyJwtCallback: options.callbacks.verifyJwt,
    errorMessage: 'Error verifiying credential request proof jwt',
    expectedNonce: options.expectedNonce,
    expectedAudience: options.credentialIssuer,
    expectedIssuer: options.clientId,
    now: options.now,
  })

  let keyAttestationResult: VerifyKeyAttestationJwtReturn | undefined = undefined
  // Check the jwt is signed with an key from attested_keys in the key_attestation jwt
  if (header.key_attestation) {
    keyAttestationResult = await verifyKeyAttestationJwt({
      callbacks: options.callbacks,
      keyAttestationJwt: header.key_attestation,
      use: 'proof_type.jwt',
    })

    const isSigedWithAttestedKey = await isJwkInSet({
      jwk: signer.publicJwk,
      jwks: keyAttestationResult.payload.attested_keys,
      callbacks: options.callbacks,
    })

    if (!isSigedWithAttestedKey) {
      throw new Oid4vciError(
        `Credential request jwt proof is not signed with a key in the 'key_attestation' jwt payload 'attested_keys'`
      )
    }
  }

  return {
    header,
    payload,
    signer,
    keyAttestation: keyAttestationResult,
  }
}
