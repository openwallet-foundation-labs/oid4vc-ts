import { Oauth2Error, zAlgValueNotNone } from '@openid4vc/oauth2'
import { parseWithErrorHandling } from '@openid4vc/utils'
import { z } from 'zod'

export const zJarmSignOnlyClientMetadata = z.object({
  authorization_signed_response_alg: zAlgValueNotNone,

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
  const parsedClientMeta = parseWithErrorHandling(
    z.union([zJarmEncryptOnlyClientMetadata, zJarmSignOnlyClientMetadata, zJarmSignEncryptClientMetadata]),
    client_metadata,
    'Invalid jarm client metadata.'
  )

  const SignEncrypt = zJarmSignEncryptClientMetadata.safeParse(parsedClientMeta)
  if (SignEncrypt.success) {
    return {
      type: 'sign_encrypt',
      client_metadata: {
        ...SignEncrypt.data,
        authorization_encrypted_response_enc: client_metadata.authorization_encrypted_response_enc,
      },
    } as const
  }

  const encryptOnly = zJarmEncryptOnlyClientMetadata.safeParse(parsedClientMeta)
  if (encryptOnly.success) {
    return {
      type: 'encrypt',
      client_metadata: {
        ...encryptOnly.data,
        authorization_encrypted_response_enc: parsedClientMeta.authorization_encrypted_response_enc,
      },
    } as const
  }

  // this must be the last entry
  const signOnly = zJarmSignOnlyClientMetadata.safeParse(parsedClientMeta)
  if (signOnly.success) {
    return {
      type: 'sign',
      client_metadata: {
        ...signOnly.data,
        authorization_signed_response_alg: parsedClientMeta.authorization_signed_response_alg,
      },
    } as const
  }

  throw new Oauth2Error('Invalid jarm client metadata. Failed to parse.')
})
export type JarmClientMetadataParsed = z.infer<typeof zJarmClientMetadataParsed>
