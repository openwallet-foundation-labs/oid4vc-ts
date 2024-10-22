import type { Jwk } from '../../../common/validation/v-common'
import type { CredentialRequestJwtProofTypeHeader, CredentialRequestJwtProofTypePayload } from './v-jwt-proof-type'

// TODO: move to generic place
type JwtSigner =
  | {
      method: 'did'
      didUrl: string
    }
  | {
      method: 'jwk'
      jwk: Jwk
    }
  | {
      method: 'x5c'
      x5c: string[]
    }
  // In case of custom nothing will be added to the header
  | {
      method: 'custom'
    }

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

  alg: string

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
    alg: options.alg,
    typ: 'openid4vci-proof+jwt',
  }

  if (options.signer.method === 'did') {
    header.kid = options.signer.didUrl
  } else if (options.signer.method === 'jwk') {
    header.jwk = options.signer.jwk
  } else if (options.signer.method === 'x5c') {
    header.x5c = options.signer.x5c
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
