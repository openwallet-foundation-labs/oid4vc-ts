import { type CallbackContext, type JwtSigner, jwtHeaderFromJwtSigner } from '@openid4vc/oauth2'
import { dateToSeconds, parseWithErrorHandling } from '@openid4vc/utils'
import type { CredentialIssuerMetadata } from './z-credential-issuer-metadata'
import {
  type SignedCredentialIssuerMetadataHeader,
  type SignedCredentialIssuerMetadataPayload,
  zSignedCredentialIssuerMetadataHeader,
  zSignedCredentialIssuerMetadataPayload,
} from './z-signed-credential-issuer-metadata'

export interface CreateSignedCredentialIssuerMetadataJwtOptions {
  /**
   * The credential issuer metadata to include in the jwt
   */
  credentialIssuerMetadata: CredentialIssuerMetadata

  /**
   * The date when the credential issuer metadata was issued. If not provided the current time will be used.
   */
  issuedAt?: Date

  /**
   * The date when the credential issuer metadata will expire.
   */
  expiresAt?: Date

  /**
   * Signer of the credential issuer metadata jwt
   */
  signer: JwtSigner

  /**
   * The issuer of the issuer metadata jwt. This field is optional
   */
  issuer?: string

  /**
   * Callbacks used for creating the credential issuer metadata jwt
   */
  callbacks: Pick<CallbackContext, 'signJwt'>

  /**
   * Additional payload to include in the credential issuer metadata jwt payload. Will be applied after
   * any default claims that are included, so add claims with caution.
   */
  additionalPayload?: Record<string, unknown>
}

export async function createSignedCredentialIssuerMetadataJwt(
  options: CreateSignedCredentialIssuerMetadataJwtOptions
): Promise<string> {
  const header = parseWithErrorHandling(zSignedCredentialIssuerMetadataHeader, {
    ...jwtHeaderFromJwtSigner(options.signer),
    typ: 'openidvci-issuer-metadata+jwt',
  } satisfies SignedCredentialIssuerMetadataHeader)

  const payload = parseWithErrorHandling(zSignedCredentialIssuerMetadataPayload, {
    ...options.credentialIssuerMetadata,
    sub: options.credentialIssuerMetadata.credential_issuer,
    iat: dateToSeconds(options.issuedAt),
    exp: options.expiresAt ? dateToSeconds(options.expiresAt) : undefined,
    iss: options.issuer,
    ...options.additionalPayload,
  } satisfies SignedCredentialIssuerMetadataPayload)

  const { jwt } = await options.callbacks.signJwt(options.signer, { header, payload })
  return jwt
}
