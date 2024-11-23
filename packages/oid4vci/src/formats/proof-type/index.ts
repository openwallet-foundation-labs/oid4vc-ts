import type { AttestationProofTypeIdentifier } from './attestation/v-attestation-proof-type'
import type { JwtProofTypeIdentifier } from './jwt/v-jwt-proof-type'

// jwt
export {
  type JwtProofTypeIdentifier,
  vCredentialRequestProofJwt,
  vJwtProofTypeIdentifier,
} from './jwt/v-jwt-proof-type'

// attestation
export {
  type AttestationProofTypeIdentifier,
  vCredentialRequestProofAttestation,
  vAttestationProofTypeIdentifier,
} from './attestation/v-attestation-proof-type'

export type ProofTypeIdentifier = JwtProofTypeIdentifier | AttestationProofTypeIdentifier
