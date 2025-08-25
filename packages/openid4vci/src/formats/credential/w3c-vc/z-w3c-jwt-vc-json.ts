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
    type: z.array(z.string()).nonempty(),
  })
  .passthrough()

const zJwtVcJsonCredentialDefinitionDraft14 = zJwtVcJsonCredentialDefinition.extend({
  credentialSubject: zW3cVcCredentialSubjectDraft14.optional(),
})

export const zJwtVcJsonCredentialIssuerMetadata = zCredentialConfigurationSupportedCommon.extend({
  format: zJwtVcJsonFormatIdentifier,
  credential_definition: zJwtVcJsonCredentialDefinition,
  credential_metadata: zCredentialConfigurationSupportedCommonCredentialMetadata
    .extend({
      claims: zIssuerMetadataClaimsDescription.optional(),
    })
    .optional(),
})

export const zJwtVcJsonCredentialIssuerMetadataDraft15 = zCredentialConfigurationSupportedCommonDraft15.extend({
  format: zJwtVcJsonFormatIdentifier,
  credential_definition: zJwtVcJsonCredentialDefinition,
  claims: zIssuerMetadataClaimsDescription.optional(),
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
    types: z.array(z.string()),
    credentialSubject: zW3cVcCredentialSubjectDraft14.optional(),
  })
  .passthrough()

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
  .passthrough()
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
    types: z.array(z.string()),
    credentialSubject: z.optional(zW3cVcCredentialSubjectDraft14),
  })
  .passthrough()

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
  .passthrough()
  .transform(({ credential_definition: { type, ...credentialDefinition }, ...rest }) => ({
    ...rest,
    types: type,
    ...credentialDefinition,
  }))
  .pipe(zJwtVcJsonCredentialRequestDraft11)
