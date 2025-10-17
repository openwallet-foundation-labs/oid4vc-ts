import z from 'zod'
import {
  zCredentialConfigurationSupportedClaimsDraft14,
  zIssuerMetadataClaimsDescription,
} from '../../../metadata/credential-issuer/z-claims-description'
import {
  zCredentialConfigurationSupportedCommon,
  zCredentialConfigurationSupportedCommonCredentialMetadata,
  zCredentialConfigurationSupportedCommonDraft15,
} from '../../../metadata/credential-issuer/z-credential-configuration-supported-common'

/**
 * @deprecated format has been deprecated in favor of "dc+sd-jwt" since Draft 23
 * of the OpenID for Verifiable Presentations specification. Please update your
 * implementations accordingly.
 */
export const zLegacySdJwtVcFormatIdentifier = z.literal('vc+sd-jwt')

/**
 * @deprecated format has been deprecated in favor of "dc+sd-jwt" since Draft 23
 * of the OpenID for Verifiable Presentations specification. Please update your
 * implementations accordingly.
 */
export type LegacySdJwtVcFormatIdentifier = z.infer<typeof zLegacySdJwtVcFormatIdentifier>

/**
 * @deprecated format has been deprecated in favor of "dc+sd-jwt" since Draft 23
 * of the OpenID for Verifiable Presentations specification. Please update your
 * implementations accordingly.
 */
export const zLegacySdJwtVcCredentialIssuerMetadataV1 = zCredentialConfigurationSupportedCommon.extend({
  vct: z.string(),
  format: zLegacySdJwtVcFormatIdentifier,
  order: z.optional(z.array(z.string())),
  credential_metadata: zCredentialConfigurationSupportedCommonCredentialMetadata
    .extend({
      claims: z.array(zIssuerMetadataClaimsDescription).optional(),
    })
    .optional(),
  credential_definition: z.optional(z.never()),
})

/**
 * @deprecated format has been deprecated in favor of "dc+sd-jwt" since Draft 23
 * of the OpenID for Verifiable Presentations specification. Please update your
 * implementations accordingly.
 */
export const zLegacySdJwtVcCredentialIssuerMetadataDraft14 = zCredentialConfigurationSupportedCommonDraft15.extend({
  vct: z.string(),
  format: zLegacySdJwtVcFormatIdentifier,
  claims: z.optional(zCredentialConfigurationSupportedClaimsDraft14),
  order: z.optional(z.array(z.string())),
  credential_definition: z.optional(z.never()),
})

/**
 * @deprecated format has been deprecated in favor of "dc+sd-jwt" since Draft 23
 * of the OpenID for Verifiable Presentations specification. Please update your
 * implementations accordingly.
 */
export const zLegacySdJwtVcCredentialRequestFormatDraft14 = z.object({
  format: zLegacySdJwtVcFormatIdentifier,
  vct: z.string(),
  claims: z.optional(zCredentialConfigurationSupportedClaimsDraft14),
  credential_definition: z.optional(z.never()),
})
