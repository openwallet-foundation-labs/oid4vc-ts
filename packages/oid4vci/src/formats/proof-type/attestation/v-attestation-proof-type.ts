import { vCompactJwt } from '@openid4vc/oauth2'
import {
  type KeyAttestationJwtHeader,
  vKeyAttestationJwtHeader,
  vKeyAttestationJwtPayloadForUse,
} from '../../../key-attestation/v-key-attestation'
import z from 'zod'

export const vAttestationProofTypeIdentifier = z.literal('attestation')
export const attestationProofTypeIdentifier = vAttestationProofTypeIdentifier.value
export type AttestationProofTypeIdentifier = z.infer<typeof vAttestationProofTypeIdentifier>

export const vCredentialRequestProofAttestation = z.object({
  proof_type: vAttestationProofTypeIdentifier,
  attestation: vCompactJwt,
})

export const vCredentialRequestAttestationProofTypeHeader = vKeyAttestationJwtHeader
export type CredentialRequestAttestationProofTypeHeader = KeyAttestationJwtHeader

export const vCredentialRequestAttestationProofTypePayload = vKeyAttestationJwtPayloadForUse('proof_type.attestation')
export type CredentialRequestAttestationProofTypePayload = z.infer<typeof vCredentialRequestAttestationProofTypePayload>
