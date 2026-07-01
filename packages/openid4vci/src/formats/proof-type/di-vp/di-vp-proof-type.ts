import type { CallbackContext } from '@openid4vc/oauth2'
import { Openid4vciError } from '../../../error/Openid4vciError'

export interface VerifyCredentialRequestDiVpProofOptions {
  /**
   * The di_vp proof — a W3C Verifiable Presentation
   */
  vp: Record<string, unknown>

  /**
   * Expected nonce. Should be a c_nonce previously shared with the wallet
   */
  expectedNonce?: string

  /**
   * Date at which the nonce will expire
   */
  nonceExpiresAt?: Date

  /**
   * The credential issuer identifier, will be matched against the DataIntegrityProof's `domain`.
   */
  credentialIssuer: string

  /**
   * Current time, if not provided a new date instance will be created
   */
  now?: Date

  /**
   * Callbacks required for the di_vp proof verification.
   */
  callbacks: Pick<CallbackContext, 'verifyDataIntegrityProof'>
}

export async function verifyCredentialRequestDiVpProof(options: VerifyCredentialRequestDiVpProofOptions) {
  const now = options.now?.getTime() ?? Date.now()
  if (options.nonceExpiresAt && now > options.nonceExpiresAt.getTime()) {
    throw new Openid4vciError('Nonce used for credential request proof expired')
  }

  const rawProof = options.vp.proof
  const proof = (Array.isArray(rawProof) ? rawProof[0] : rawProof) as Record<string, unknown> | undefined

  if (!proof || typeof proof !== 'object') {
    throw new Openid4vciError(`di_vp proof is missing a 'proof' entry`)
  }
  if (proof.type !== 'DataIntegrityProof') {
    throw new Openid4vciError(`di_vp proof 'proof.type' must be 'DataIntegrityProof'`)
  }
  if (!proof.cryptosuite || typeof proof.cryptosuite !== 'string') {
    throw new Openid4vciError(`di_vp proof is missing required 'proof.cryptosuite'`)
  }
  if (proof.proofPurpose !== 'authentication') {
    throw new Openid4vciError(`di_vp proof 'proof.proofPurpose' must be 'authentication'`)
  }
  if (proof.domain !== options.credentialIssuer) {
    throw new Openid4vciError(`di_vp proof 'proof.domain' does not match the credential issuer identifier`)
  }
  if (options.expectedNonce !== undefined) {
    if (proof.challenge !== options.expectedNonce) {
      throw new Openid4vciError(`di_vp proof 'proof.challenge' does not match the expected nonce`)
    }
  } else if (proof.challenge !== undefined) {
    throw new Openid4vciError(`di_vp proof 'proof.challenge' must not be present when no nonce was issued`)
  }
  if (!proof.verificationMethod || typeof proof.verificationMethod !== 'string') {
    throw new Openid4vciError(`di_vp proof is missing required 'proof.verificationMethod'`)
  }

  if (!options.callbacks.verifyDataIntegrityProof) {
    throw new Openid4vciError('Cannot verify di_vp proof: no verifyDataIntegrityProof callback configured')
  }

  const result = await options.callbacks.verifyDataIntegrityProof(proof, options.vp)
  if (!result.verified) {
    throw new Openid4vciError('Error verifying credential request di_vp proof')
  }

  return {
    vp: options.vp,
    proof,
    signerJwk: result.signerJwk,
  }
}
