import {
  type CreateKeyAttestationJwtOptions,
  createKeyAttestationJwt,
  type VerifyKeyAttestationJwtOptions,
  verifyKeyAttestationJwt,
} from '../../../key-attestation/key-attestation'

export interface CreateCredentialRequestAttestationProofOptions extends Omit<CreateKeyAttestationJwtOptions, 'use'> {
  /**
   * Nonce to use in the attestation. Should be derived from the c_nonce
   *
   * Required because the attestation is created for 'attestation' proof types
   */
  nonce: string

  /**
   * The date when the key attestation will expire.
   */
  expiresAt: Date
}

export async function createCredentialRequestAttestationProof(
  options: CreateCredentialRequestAttestationProofOptions
): Promise<string> {
  return createKeyAttestationJwt({
    ...options,
    use: 'proof_type.attestation',
  })
}

export interface VerifyCredentialRequestAttestationProofOptions extends Omit<VerifyKeyAttestationJwtOptions, 'use'> {}
export async function verifyCredentialRequestAttestationProof(options: VerifyCredentialRequestAttestationProofOptions) {
  const verificationResult = await verifyKeyAttestationJwt({
    ...options,
    use: 'proof_type.attestation',
  })

  return verificationResult
}
