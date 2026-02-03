import z from 'zod'
import { zIssuerMetadataClaimsDescription } from '../../../metadata/credential-issuer/z-claims-description'
import {
  zCredentialConfigurationSupportedCommon,
  zCredentialConfigurationSupportedCommonCredentialMetadata,
  zCredentialConfigurationSupportedCommonDraft15,
} from '../../../metadata/credential-issuer/z-credential-configuration-supported-common'

export const zSdJwtW3VcFormatIdentifier = z.literal('vc+sd-jwt')
export type SdJwtW3VcFormatIdentifier = z.infer<typeof zSdJwtW3VcFormatIdentifier>

const zSdJwtW3VcCredentialDefinition = z
  .object({
    type: z.tuple([z.string()], z.string()),
  })
  .loose()

export const zSdJwtW3VcCredentialIssuerMetadata = zCredentialConfigurationSupportedCommon.extend({
  format: zSdJwtW3VcFormatIdentifier,
  credential_definition: zSdJwtW3VcCredentialDefinition,
  credential_signing_alg_values_supported: z.array(z.string()).optional(),
  credential_metadata: zCredentialConfigurationSupportedCommonCredentialMetadata
    .extend({
      claims: z.array(zIssuerMetadataClaimsDescription).optional(),
    })
    .optional(),

  // FIXME(vc+sd-jwt): remove when dropping support for legacy vc+sd-jwt. Allows type narrowing.
  vct: z.optional(z.never()),
})

export const zSdJwtW3VcCredentialIssuerMetadataDraft15 = zCredentialConfigurationSupportedCommonDraft15.extend({
  format: zSdJwtW3VcFormatIdentifier,
  credential_definition: zSdJwtW3VcCredentialDefinition,
  claims: z.array(zIssuerMetadataClaimsDescription).optional(),

  // FIXME(vc+sd-jwt): remove when dropping support for legacy vc+sd-jwt. Allows type narrowing.
  vct: z.optional(z.never()),
})

export const zSdJwtW3VcCredentialRequestFormatDraft14 = z.object({
  format: zSdJwtW3VcFormatIdentifier,
  credential_definition: zSdJwtW3VcCredentialDefinition,

  // FIXME(vc+sd-jwt): remove when dropping support for legacy vc+sd-jwt. Allows type narrowing.
  vct: z.optional(z.never()),
})
