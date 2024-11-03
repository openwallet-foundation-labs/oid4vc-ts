import { type JwtSigner, jwtHeaderFromJwtSigner } from '@animo-id/oauth2'
import type { CredentialRequestJwtProofTypeHeader, CredentialRequestJwtProofTypePayload } from './v-jwt-proof-type'

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

  signer: JwtSigner
}

export interface CreateCredentialRequestJwtProofResult {
  header: CredentialRequestJwtProofTypeHeader
  payload: CredentialRequestJwtProofTypePayload
}

export function createCredentialRequestJwtProof(
  options: CreateCredentialRequestJwtProofOptions
): CreateCredentialRequestJwtProofResult {
  const header: CredentialRequestJwtProofTypeHeader = {
    ...jwtHeaderFromJwtSigner(options.signer),
    typ: 'openid4vci-proof+jwt',
  }

  return {
    payload: {
      nonce: options.nonce,
      aud: options.credentialIssuer,
      iat: Math.floor((options.issuedAt ?? new Date()).getTime() / 1000),
      iss: options.clientId,
    },
    header,
  }
}
