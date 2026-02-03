import z from 'zod'
import { zIssuerMetadataClaimsDescription } from '../../../metadata/credential-issuer/z-claims-description'
import {
  zCredentialConfigurationSupportedCommon,
  zCredentialConfigurationSupportedCommonCredentialMetadata,
  zCredentialConfigurationSupportedCommonDraft15,
} from '../../../metadata/credential-issuer/z-credential-configuration-supported-common'
import { zW3cVcCredentialSubjectDraft14 } from './z-w3c-vc-common'

export const zJwtVcJsonFormatIdentifier = z.literal('jwt_vc_json')
export type JwtVcJsonFormatIdentifier = z.infer<typeof zJwtVcJsonFormatIdentifier>

const zJwtVcJsonCredentialDefinition = z
  .object({
    type: z.tuple([z.string()], z.string()),
  })
  .loose()

const zJwtVcJsonCredentialDefinitionDraft14 = zJwtVcJsonCredentialDefinition.extend({
  credentialSubject: zW3cVcCredentialSubjectDraft14.optional(),
})

export const zJwtVcJsonCredentialIssuerMetadata = zCredentialConfigurationSupportedCommon.extend({
  format: zJwtVcJsonFormatIdentifier,
  credential_definition: zJwtVcJsonCredentialDefinition,
  credential_signing_alg_values_supported: z.array(z.string()).optional(),
  credential_metadata: zCredentialConfigurationSupportedCommonCredentialMetadata
    .extend({
      claims: z.array(zIssuerMetadataClaimsDescription).optional(),
    })
    .optional(),
})

export const zJwtVcJsonCredentialIssuerMetadataDraft15 = zCredentialConfigurationSupportedCommonDraft15.extend({
  format: zJwtVcJsonFormatIdentifier,
  credential_definition: zJwtVcJsonCredentialDefinition,
  claims: z.array(zIssuerMetadataClaimsDescription).optional(),
})

export const zJwtVcJsonCredentialIssuerMetadataDraft14 = zCredentialConfigurationSupportedCommonDraft15.extend({
  format: zJwtVcJsonFormatIdentifier,
  credential_definition: zJwtVcJsonCredentialDefinitionDraft14,
  order: z.array(z.string()).optional(),
})

export const zJwtVcJsonCredentialIssuerMetadataDraft11 = z
  .object({
    format: zJwtVcJsonFormatIdentifier,
    order: z.array(z.string()).optional(),
    // Credential definition was spread on top level instead of a separatey property in v11
    // As well as using types instead of type
    types: z.tuple([z.string()], z.string()),
    credentialSubject: zW3cVcCredentialSubjectDraft14.optional(),
  })
  .loose()

export const zJwtVcJsonCredentialIssuerMetadataDraft11To14 = zJwtVcJsonCredentialIssuerMetadataDraft11.transform(
  ({ types, credentialSubject, ...rest }) => ({
    ...rest,
    credential_definition: {
      type: types,
      // Prevent weird typing issue with optional vs undefined
      ...(credentialSubject ? { credentialSubject } : {}),
    },
  })
)

export const zJwtVcJsonCredentialIssuerMetadataDraft14To11 = zJwtVcJsonCredentialIssuerMetadataDraft14
  .loose()
  .transform(({ credential_definition: { type, ...credentialDefinition }, ...rest }) => ({
    ...rest,
    types: type,
    ...credentialDefinition,
  }))
  .pipe(zJwtVcJsonCredentialIssuerMetadataDraft11)

export const zJwtVcJsonCredentialRequestFormatDraft14 = z.object({
  format: zJwtVcJsonFormatIdentifier,
  credential_definition: zJwtVcJsonCredentialDefinition,
})

export const zJwtVcJsonCredentialRequestDraft11 = z
  .object({
    format: zJwtVcJsonFormatIdentifier,
    // Credential definition was spread on top level instead of a separatey property in v11
    // As well as using types instead of type
    types: z.tuple([z.string()], z.string()),
    credentialSubject: z.optional(zW3cVcCredentialSubjectDraft14),
  })
  .loose()

export const zJwtVcJsonCredentialRequestDraft11To14 = zJwtVcJsonCredentialRequestDraft11.transform(
  ({ types, credentialSubject, ...rest }) => {
    return {
      ...rest,
      credential_definition: {
        type: types,
        // Prevent weird typing issue with optional vs undefined
        ...(credentialSubject ? { credentialSubject } : {}),
      },
    }
  }
)

export const zJwtVcJsonCredentialRequestDraft14To11 = zJwtVcJsonCredentialRequestFormatDraft14
  .loose()
  .transform(({ credential_definition: { type, ...credentialDefinition }, ...rest }) => ({
    ...rest,
    types: type,
    ...credentialDefinition,
  }))
  .pipe(zJwtVcJsonCredentialRequestDraft11)
