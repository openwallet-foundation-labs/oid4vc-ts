import { zCompactJwt } from '@openid4vc/oauth2'
import z from 'zod'
import {
  type KeyAttestationJwtHeader,
  zKeyAttestationJwtHeader,
  zKeyAttestationJwtPayloadForUse,
} from '../../../key-attestation/z-key-attestation'

export const zAttestationProofTypeIdentifier = z.literal('attestation')
export const attestationProofTypeIdentifier = zAttestationProofTypeIdentifier.value
export type AttestationProofTypeIdentifier = z.infer<typeof zAttestationProofTypeIdentifier>

export const zCredentialRequestProofAttestation = z.object({
  proof_type: zAttestationProofTypeIdentifier,
  attestation: zCompactJwt,
})

export const zCredentialRequestAttestationProofTypeHeader = zKeyAttestationJwtHeader
export type CredentialRequestAttestationProofTypeHeader = KeyAttestationJwtHeader

export const zCredentialRequestAttestationProofTypePayload = zKeyAttestationJwtPayloadForUse('proof_type.attestation')
export type CredentialRequestAttestationProofTypePayload = z.infer<typeof zCredentialRequestAttestationProofTypePayload>
