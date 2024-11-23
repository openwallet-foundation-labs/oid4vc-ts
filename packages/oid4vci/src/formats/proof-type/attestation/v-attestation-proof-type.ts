import * as v from 'valibot'

import { vCompactJwt } from '@animo-id/oauth2'
import {
  type KeyAttestationJwtHeader,
  vKeyAttestationJwtHeader,
  vKeyAttestationJwtPayloadForUse,
} from '../../../key-attestation/v-key-attestation'

export const vAttestationProofTypeIdentifier = v.literal('attestation')
export const attestationProofTypeIdentifier = vAttestationProofTypeIdentifier.literal
export type AttestationProofTypeIdentifier = v.InferOutput<typeof vAttestationProofTypeIdentifier>

export const vCredentialRequestProofAttestation = v.object({
  proof_type: vAttestationProofTypeIdentifier,
  attestation: vCompactJwt,
})

export const vCredentialRequestAttestationProofTypeHeader = vKeyAttestationJwtHeader
export type CredentialRequestAttestationProofTypeHeader = KeyAttestationJwtHeader

export const vCredentialRequestAttestationProofTypePayload = vKeyAttestationJwtPayloadForUse('proof_type.attestation')
export type CredentialRequestAttestationProofTypePayload = v.InferOutput<
  typeof vCredentialRequestAttestationProofTypePayload
>
