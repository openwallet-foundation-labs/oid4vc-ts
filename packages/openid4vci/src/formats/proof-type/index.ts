import type { AttestationProofTypeIdentifier } from './attestation/z-attestation-proof-type'
import type { JwtProofTypeIdentifier } from './jwt/z-jwt-proof-type'

// attestation
export {
  type AttestationProofTypeIdentifier,
  zAttestationProofTypeIdentifier,
  zCredentialRequestProofAttestation,
} from './attestation/z-attestation-proof-type'
// jwt
export {
  type JwtProofTypeIdentifier,
  zCredentialRequestProofJwt,
  zJwtProofTypeIdentifier,
} from './jwt/z-jwt-proof-type'

export type ProofTypeIdentifier = JwtProofTypeIdentifier | AttestationProofTypeIdentifier
