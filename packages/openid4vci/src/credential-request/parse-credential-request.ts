import { parseWithErrorHandling } from '@openid4vc/utils'
import z from 'zod'
import type { CredentialFormatIdentifier } from '../formats/credential'
import { attestationProofTypeIdentifier } from '../formats/proof-type/attestation/z-attestation-proof-type'
import { jwtProofTypeIdentifier } from '../formats/proof-type/jwt/z-jwt-proof-type'
import {
  type CredentialRequest,
  type CredentialRequestFormatSpecific,
  allCredentialRequestFormatIdentifiers,
  allCredentialRequestFormats,
  zCredentialRequest,
} from './z-credential-request'
import {
  type CredentialRequestProofsFormatSpecific,
  allCredentialRequestProofs,
  zCredentialRequestProofs,
} from './z-credential-request-common'

export interface ParseCredentialRequestOptions {
  credentialRequest: Record<string, unknown>
}

export interface ParseCredentialRequestReturn {
  /**
   * If the request was for a `format` that is known to this library it will have the
   * format specific data defined here. Will not be defined if the request is for an unknown format,
   * or if `credential_identifier` is used.
   */
  format?: CredentialRequestFormatSpecific

  /**
   * If the request contains `proof` or `proofs` with a `proof_type` that is known to this
   * library it will have the proof type specific data defined here. Will not be defined
   * if the `proof_type` is not known or no `proof` or `proofs` were included.
   *
   * The `proof` property is parsed to the new proofs structure and the entries will
   * always only have a single entry in this case.
   *
   * NOTE: this value being `undefined` does NOT mean there were no proofs.
   * It means that either there were no proofs, or that the proof format is not
   * known to this library
   */
  proofs?: CredentialRequestProofsFormatSpecific

  /**
   * If authorization details were used a `credential_identifier` will be included
   * in the request. Will not be defined if `format` is defined.
   */
  credentialIdentifier?: string

  /**
   * The validated credential request. If both `format` and `credentialIdentifier` are
   * undefined you can still handle the request by using this object directly.
   */
  credentialRequest: CredentialRequest
}

export function parseCredentialRequest(options: ParseCredentialRequestOptions): ParseCredentialRequestReturn {
  const credentialRequest = parseWithErrorHandling(
    zCredentialRequest,
    options.credentialRequest,
    'Error validating credential request'
  )
  let proofs: CredentialRequestProofsFormatSpecific | undefined = undefined

  // Try to parse the known proofs from the `proofs` object
  const knownProofs = zCredentialRequestProofs.strict().safeParse(credentialRequest.proofs)
  if (knownProofs.success) {
    proofs = knownProofs.data
  }

  // Try to parse the known proof from the `proof`
  const knownProof = z.union(allCredentialRequestProofs).safeParse(credentialRequest.proof)
  if (knownProof.success && knownProof.data.proof_type === jwtProofTypeIdentifier) {
    proofs = { [jwtProofTypeIdentifier]: [knownProof.data.jwt] }
  } else if (knownProof.success && knownProof.data.proof_type === attestationProofTypeIdentifier) {
    proofs = { [attestationProofTypeIdentifier]: [knownProof.data.attestation] }
  }

  if (credentialRequest.credential_identifier) {
    return {
      credentialIdentifier: credentialRequest.credential_identifier as string,
      credentialRequest,
      proofs,
    }
  }

  if (
    credentialRequest.format &&
    allCredentialRequestFormatIdentifiers.includes(credentialRequest.format as CredentialFormatIdentifier)
  ) {
    return {
      // Removes all claims that are not specific to this format
      format: parseWithErrorHandling(
        z.union(allCredentialRequestFormats),
        credentialRequest,
        'Unable to validate format specific properties from credential request'
      ),
      credentialRequest,
      proofs,
    }
  }

  return {
    credentialRequest,
    proofs,
  }
}
