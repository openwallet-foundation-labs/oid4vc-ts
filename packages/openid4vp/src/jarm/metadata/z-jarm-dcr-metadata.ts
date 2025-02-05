import { Oauth2Error } from '@openid4vc/oauth2'
import { z } from 'zod'

export const zJarmSignOnlyClientMetadata = z.object({
  authorization_signed_response_alg: z.string(),

  authorization_encrypted_response_alg: z.optional(z.never()),
  authorization_encrypted_response_enc: z.optional(z.never()),
})
export type JarmSignOnlyClientMetadata = z.infer<typeof zJarmSignOnlyClientMetadata>

export const zJarmEncryptOnlyClientMetadata = z.object({
  authorization_signed_response_alg: z.optional(z.never()),
  authorization_encrypted_response_alg: z.string(),

  authorization_encrypted_response_enc: z.optional(z.string()),
})
export type JarmEncryptOnlyClientMetadata = z.infer<typeof zJarmEncryptOnlyClientMetadata>

export const zJarmSignEncryptClientMetadata = z.object({
  authorization_signed_response_alg: zJarmSignOnlyClientMetadata.shape.authorization_signed_response_alg,
  authorization_encrypted_response_alg: zJarmEncryptOnlyClientMetadata.shape.authorization_encrypted_response_alg,
  authorization_encrypted_response_enc: zJarmEncryptOnlyClientMetadata.shape.authorization_encrypted_response_enc,
})
export type JarmSignEncryptClientMetadata = z.infer<typeof zJarmSignEncryptClientMetadata>

/**
 * Clients may register their public encryption keys using the jwks_uri or jwks metadata parameters.
 */
export const zJarmClientMetadata = z.object({
  authorization_signed_response_alg: z.optional(zJarmSignOnlyClientMetadata.shape.authorization_signed_response_alg),
  authorization_encrypted_response_alg: z.optional(
    zJarmEncryptOnlyClientMetadata.shape.authorization_encrypted_response_alg
  ),
  authorization_encrypted_response_enc: z.optional(
    zJarmEncryptOnlyClientMetadata.shape.authorization_encrypted_response_enc
  ),
})
export type JarmClientMetadata = z.infer<typeof zJarmClientMetadata>

export const zJarmClientMetadataParsed = zJarmClientMetadata.transform((client_metadata) => {
  const SignEncrypt = zJarmSignEncryptClientMetadata.safeParse(client_metadata)
  if (SignEncrypt.success) {
    return {
      type: 'sign_encrypt',
      client_metadata: {
        ...SignEncrypt.data,
        authorization_encrypted_response_enc: client_metadata.authorization_encrypted_response_enc ?? 'A128CBC-HS256',
      },
    } as const
  }

  const encryptOnly = zJarmEncryptOnlyClientMetadata.safeParse(client_metadata)
  if (encryptOnly.success) {
    return {
      type: 'encrypt',
      client_metadata: {
        ...encryptOnly.data,
        authorization_encrypted_response_enc: client_metadata.authorization_encrypted_response_enc ?? 'A128CBC-HS256',
      },
    } as const
  }

  // this must be the last entry
  const signOnly = zJarmSignOnlyClientMetadata.safeParse(client_metadata)
  if (signOnly.success) {
    return {
      type: 'sign',
      client_metadata: {
        ...signOnly.data,
        authorization_signed_response_alg: client_metadata.authorization_signed_response_alg ?? 'RS256',
      },
    } as const
  }

  throw new Oauth2Error('Invalid client metadata')
})
export type JarmClientMetadataParsed = z.infer<typeof zJarmClientMetadataParsed>
