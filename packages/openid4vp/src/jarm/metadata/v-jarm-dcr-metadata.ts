import { Oauth2Error } from '@openid4vc/oauth2'
import * as v from 'valibot'

export const vJarmSignOnlyClientMetadata = v.object({
  authorization_signed_response_alg: v.pipe(
    v.string(),
    v.description(
      'JWA. If this is specified, the response will be signed using JWS and the configured algorithm. The algorithm none is not allowed.'
    )
  ),

  authorization_encrypted_response_alg: v.optional(v.never()),
  authorization_encrypted_response_enc: v.optional(v.never()),
})
export type JarmSignOnlyClientMetadata = v.InferOutput<typeof vJarmSignOnlyClientMetadata>

export const vJarmEncryptOnlyClientMetadata = v.object({
  authorization_signed_response_alg: v.optional(v.never()),
  authorization_encrypted_response_alg: v.pipe(
    v.string(),
    v.description(
      'JWE alg algorithm JWA. If both signing and encryption are requested, the response will be signed then encrypted with the provided algorithm.'
    )
  ),

  authorization_encrypted_response_enc: v.pipe(
    v.optional(v.string()),
    v.description(
      'JWE enc algorithm JWA. If both signing and encryption are requested, the response will be signed then encrypted with the provided algorithm.'
    )
  ),
})
export type JarmEncryptOnlyClientMetadata = v.InferOutput<typeof vJarmEncryptOnlyClientMetadata>

export const vJarmSignEncryptClientMetadata = v.object({
  authorization_signed_response_alg: vJarmSignOnlyClientMetadata.entries.authorization_signed_response_alg,
  authorization_encrypted_response_alg: vJarmEncryptOnlyClientMetadata.entries.authorization_encrypted_response_alg,
  authorization_encrypted_response_enc: vJarmEncryptOnlyClientMetadata.entries.authorization_encrypted_response_enc,
})
export type JarmSignEncryptClientMetadata = v.InferOutput<typeof vJarmSignEncryptClientMetadata>

/**
 * Clients may register their public encryption keys using the jwks_uri or jwks metadata parameters.
 */
export const JarmClientMetadata = v.object({
  authorization_signed_response_alg: v.optional(vJarmSignOnlyClientMetadata.entries.authorization_signed_response_alg),
  authorization_encrypted_response_alg: v.optional(
    vJarmEncryptOnlyClientMetadata.entries.authorization_encrypted_response_alg
  ),
  authorization_encrypted_response_enc: v.optional(
    vJarmEncryptOnlyClientMetadata.entries.authorization_encrypted_response_enc
  ),
})
export type JarmClientMetadata = v.InferOutput<typeof JarmClientMetadata>

export const JarmClientMetadataParsed = v.pipe(
  JarmClientMetadata,
  v.transform((client_metadata) => {
    if (v.is(vJarmSignEncryptClientMetadata, client_metadata)) {
      return {
        type: 'sign_encrypt',
        client_metadata: {
          ...client_metadata,
          authorization_encrypted_response_enc: client_metadata.authorization_encrypted_response_enc ?? 'A128CBC-HS256',
        },
      } as const
    }

    if (v.is(vJarmEncryptOnlyClientMetadata, client_metadata)) {
      return {
        type: 'encrypt',
        client_metadata: {
          ...client_metadata,
          authorization_encrypted_response_enc: client_metadata.authorization_encrypted_response_enc ?? 'A128CBC-HS256',
        },
      } as const
    }

    // this must be the last entry
    if (v.is(vJarmSignOnlyClientMetadata, client_metadata)) {
      return {
        type: 'sign',
        client_metadata: {
          ...client_metadata,
          authorization_signed_response_alg: client_metadata.authorization_signed_response_alg ?? 'RS256',
        },
      } as const
    }

    throw new Oauth2Error('Invalid client metadata')
  })
)
export type JarmClientMetadataParsed = v.InferOutput<typeof JarmClientMetadataParsed>
