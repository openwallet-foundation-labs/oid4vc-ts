import type { AttestationProofTypeIdentifier } from './attestation/z-attestation-proof-type'
import type { DiVpProofTypeIdentifier } from './di-vp/z-di-vp-proof-type'
import type { JwtProofTypeIdentifier } from './jwt/z-jwt-proof-type'

// attestation
export {
  type AttestationProofTypeIdentifier,
  zAttestationProofTypeIdentifier,
  zCredentialRequestProofAttestation,
} from './attestation/z-attestation-proof-type'
// di_vp
export {
  type DiVpProofTypeIdentifier,
  diVpProofTypeIdentifier,
  zCredentialRequestProofDiVp,
  zDiVpProofTypeIdentifier,
} from './di-vp/z-di-vp-proof-type'
// jwt
export {
  type JwtProofTypeIdentifier,
  zCredentialRequestProofJwt,
  zJwtProofTypeIdentifier,
} from './jwt/z-jwt-proof-type'

export type ProofTypeIdentifier = JwtProofTypeIdentifier | AttestationProofTypeIdentifier | DiVpProofTypeIdentifier
