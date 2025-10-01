import { zCompactJwt } from '@openid4vc/oauth2'
import { type InferOutputUnion, type Simplify, zHttpsUrl } from '@openid4vc/utils'
import z from 'zod'
import {
  type CredentialFormatIdentifier,
  zJwtVcJsonCredentialIssuerMetadata,
  zJwtVcJsonCredentialIssuerMetadataDraft11To14,
  zJwtVcJsonCredentialIssuerMetadataDraft14,
  zJwtVcJsonCredentialIssuerMetadataDraft14To11,
  zJwtVcJsonCredentialIssuerMetadataDraft15,
  zJwtVcJsonFormatIdentifier,
  zJwtVcJsonLdCredentialIssuerMetadata,
  zJwtVcJsonLdCredentialIssuerMetadataDraft11To14,
  zJwtVcJsonLdCredentialIssuerMetadataDraft14,
  zJwtVcJsonLdCredentialIssuerMetadataDraft14To11,
  zJwtVcJsonLdCredentialIssuerMetadataDraft15,
  zJwtVcJsonLdFormatIdentifier,
  zLdpVcCredentialIssuerMetadata,
  zLdpVcCredentialIssuerMetadataDraft11To14,
  zLdpVcCredentialIssuerMetadataDraft14,
  zLdpVcCredentialIssuerMetadataDraft14To11,
  zLdpVcCredentialIssuerMetadataDraft15,
  zLdpVcFormatIdentifier,
  zLegacySdJwtVcCredentialIssuerMetadataDraft14,
  zMsoMdocCredentialIssuerMetadata,
  zMsoMdocCredentialIssuerMetadataDraft14,
  zMsoMdocCredentialIssuerMetadataDraft15,
  zSdJwtDcCredentialIssuerMetadata,
  zSdJwtDcCredentialIssuerMetadataDraft15,
  zSdJwtDcFormatIdentifier,
} from '../../formats/credential'
import { zLegacySdJwtVcCredentialIssuerMetadataDraft16 } from '../../formats/credential/sd-jwt-vc/z-sd-jwt-vc'
import {
  zSdJwtW3VcCredentialIssuerMetadata,
  zSdJwtW3VcCredentialIssuerMetadataDraft15,
} from '../../formats/credential/w3c-vc/z-w3c-sd-jwt-vc'
import { Openid4vciDraftVersion } from '../../version'
import {
  zCredentialConfigurationSupportedCommon,
  zCredentialConfigurationSupportedCommonDraft15,
} from './z-credential-configuration-supported-common'

const allCredentialIssuerMetadataFormats = [
  zSdJwtDcCredentialIssuerMetadata,
  zMsoMdocCredentialIssuerMetadata,
  zJwtVcJsonLdCredentialIssuerMetadata,
  zLdpVcCredentialIssuerMetadata,
  zJwtVcJsonCredentialIssuerMetadata,
  zSdJwtW3VcCredentialIssuerMetadata,
  zSdJwtW3VcCredentialIssuerMetadataDraft15,
  zLegacySdJwtVcCredentialIssuerMetadataDraft16,
  zSdJwtDcCredentialIssuerMetadataDraft15,
  zMsoMdocCredentialIssuerMetadataDraft15,
  zJwtVcJsonLdCredentialIssuerMetadataDraft15,
  zLdpVcCredentialIssuerMetadataDraft15,
  zJwtVcJsonCredentialIssuerMetadataDraft15,
  zMsoMdocCredentialIssuerMetadataDraft14,
  zLegacySdJwtVcCredentialIssuerMetadataDraft14,
  zJwtVcJsonLdCredentialIssuerMetadataDraft14,
  zLdpVcCredentialIssuerMetadataDraft14,
  zJwtVcJsonCredentialIssuerMetadataDraft14,
] as const
type CredentialIssuerMetadataFormatValidator = (typeof allCredentialIssuerMetadataFormats)[number]
export const allCredentialIssuerMetadataFormatIdentifiers = allCredentialIssuerMetadataFormats.map(
  (format) => format.shape.format.value
)

export const zCredentialConfigurationSupportedWithFormats = z
  .union([zCredentialConfigurationSupportedCommon, zCredentialConfigurationSupportedCommonDraft15])
  .transform((data, ctx) => {
    // No additional validation for unknown formats
    if (!allCredentialIssuerMetadataFormatIdentifiers.includes(data.format as CredentialFormatIdentifier)) return data

    const validators = allCredentialIssuerMetadataFormats.filter(
      (formatValidator) => formatValidator.shape.format.value === data.format
    ) as CredentialIssuerMetadataFormatValidator[]

    const result = z
      // We use object and passthrough as otherwise the non-format specific properties will be stripped
      .object({})
      .passthrough()
      .and(
        validators.length > 1
          ? z.union(
              validators as [
                CredentialIssuerMetadataFormatValidator,
                CredentialIssuerMetadataFormatValidator,
                ...CredentialIssuerMetadataFormatValidator[],
              ]
            )
          : validators[0]
      )
      .safeParse(data)

    if (result.success) {
      return result.data as Simplify<typeof result.data & typeof data>
    }

    for (const issue of result.error.issues) {
      ctx.addIssue(issue)
    }

    return z.NEVER
  })

type CredentialConfigurationSupportedCommon = z.infer<typeof zCredentialConfigurationSupportedCommon>
export type CredentialConfigurationSupportedFormatSpecific = InferOutputUnion<typeof allCredentialIssuerMetadataFormats>
export type CredentialConfigurationSupportedWithFormats = CredentialConfigurationSupportedFormatSpecific &
  CredentialConfigurationSupportedCommon
export type CredentialConfigurationsSupportedWithFormats = Record<string, CredentialConfigurationSupportedWithFormats>

export type CredentialConfigurationSupported = z.infer<typeof zCredentialConfigurationSupportedWithFormats>
export type CredentialConfigurationsSupported = Record<string, CredentialConfigurationSupported>

const zCredentialIssuerMetadataDisplayEntry = z
  .object({
    name: z.string().optional(),
    locale: z.string().optional(),
    logo: z
      .object({
        // FIXME: make required again, but need to support draft 11 first
        uri: z.string().optional(),
        alt_text: z.string().optional(),
      })
      .passthrough()
      .optional(),
  })
  .passthrough()
export type CredentialIssuerMetadataDisplayEntry = z.infer<typeof zCredentialIssuerMetadataDisplayEntry>

export type CredentialIssuerMetadata = z.infer<typeof zCredentialIssuerMetadataDraft14Draft15Draft16>
const zCredentialIssuerMetadataDraft14Draft15Draft16 = z
  .object({
    credential_issuer: zHttpsUrl,
    authorization_servers: z.array(zHttpsUrl).optional(),
    credential_endpoint: zHttpsUrl,
    deferred_credential_endpoint: zHttpsUrl.optional(),
    notification_endpoint: zHttpsUrl.optional(),

    // Added after draft 14, but needed for proper
    nonce_endpoint: zHttpsUrl.optional(),
    credential_response_encryption: z
      .object({
        alg_values_supported: z.array(z.string()),
        enc_values_supported: z.array(z.string()),
        encryption_required: z.boolean(),
      })
      .passthrough()
      .optional(),
    batch_credential_issuance: z
      .object({
        batch_size: z.number().positive(),
      })
      .passthrough()
      .optional(),
    signed_metadata: zCompactJwt.optional(),
    display: z.array(zCredentialIssuerMetadataDisplayEntry).optional(),
    credential_configurations_supported: z.record(z.string(), zCredentialConfigurationSupportedWithFormats),
  })
  .passthrough()

// Transforms credential supported to credential configuration supported format
// Ignores unknown formats
export const zCredentialConfigurationSupportedDraft11To16 = z
  .object({
    id: z.string().optional(),
    format: z.string(),
    cryptographic_suites_supported: z.array(z.string()).optional(),
    display: z
      .array(
        z
          .object({
            logo: z
              .object({
                url: z.string().url().optional(),
              })
              .passthrough()
              .optional(),
            background_image: z
              .object({
                url: z.string().url().optional(),
              })
              .passthrough()
              .optional(),
          })
          .passthrough()
      )
      .optional(),
    claims: z.any().optional(),
  })
  .passthrough()
  .transform(({ cryptographic_suites_supported, display, claims, id, ...rest }) => ({
    ...rest,
    ...(cryptographic_suites_supported
      ? { credential_signing_alg_values_supported: cryptographic_suites_supported }
      : {}),
    ...(claims || display
      ? {
          credential_metadata: {
            ...(claims ? { claims } : {}),
            ...(display
              ? {
                  display: display.map(({ logo, background_image, ...displayRest }) => ({
                    ...displayRest,
                    // url became uri and also required
                    // so if there's no url in the logo, we remove the whole logo object
                    ...(logo?.url
                      ? {
                          // TODO: we should add the other params from logo as well
                          logo: {
                            uri: logo.url,
                          },
                        }
                      : {}),

                    // TODO: we should add the other params from background_image as well
                    // url became uri and also required
                    // so if there's no url in the background_image, we remove the whole logo object
                    ...(background_image?.url
                      ? {
                          background_image: {
                            uri: background_image.url,
                          },
                        }
                      : {}),
                  })),
                }
              : {}),
          },
        }
      : {}),
  }))
  .transform((data, ctx) => {
    const formatSpecificTransformations = {
      [zLdpVcFormatIdentifier.value]: zLdpVcCredentialIssuerMetadataDraft11To14,
      [zJwtVcJsonFormatIdentifier.value]: zJwtVcJsonCredentialIssuerMetadataDraft11To14,
      [zJwtVcJsonLdFormatIdentifier.value]: zJwtVcJsonLdCredentialIssuerMetadataDraft11To14,
    } as const

    if (!Object.keys(formatSpecificTransformations).includes(data.format)) return data

    const schema = formatSpecificTransformations[data.format as keyof typeof formatSpecificTransformations]
    const result = schema.safeParse(data)
    if (result.success) return result.data
    for (const issue of result.error.issues) {
      ctx.addIssue(issue)
    }
    return z.NEVER
  })
  .pipe(zCredentialConfigurationSupportedWithFormats)

// Transforms credential configuration supported from draft 16 to draft 15
const zCredentialConfigurationSupportedDraft16To15 = zCredentialConfigurationSupportedWithFormats.transform(
  ({ credential_metadata, ...rest }) => ({
    ...credential_metadata,
    ...rest,
  })
)

// Transforms credential configuration supported to credentials_supported format
// Ignores unknown formats
const zCredentialConfigurationSupportedDraft16To11 = zCredentialConfigurationSupportedDraft16To15
  .and(
    z
      .object({
        id: z.string(),
      })
      .passthrough()
  )
  .transform(({ id, credential_signing_alg_values_supported, display, proof_types_supported, scope, ...rest }) => ({
    ...rest,
    ...(credential_signing_alg_values_supported
      ? { cryptographic_suites_supported: credential_signing_alg_values_supported }
      : {}),
    ...(display
      ? {
          display: display.map(({ logo, background_image, ...displayRest }) => {
            const { uri: logoUri, ...logoRest } = logo ?? {}
            const { uri: backgroundImageUri, ...backgroundImageRest } = background_image ?? {}
            return {
              ...displayRest,
              // draft 11 uses url, draft 13/14 uses uri
              ...(logoUri ? { logo: { url: logoUri, ...logoRest } } : {}),
              // draft 11 uses url, draft 13/14 uses uri
              ...(backgroundImageUri ? { logo: { url: backgroundImageUri, ...backgroundImageRest } } : {}),
            }
          }),
        }
      : {}),
    id,
  }))
  .pipe(
    z.union([
      zLdpVcCredentialIssuerMetadataDraft14To11,
      zJwtVcJsonCredentialIssuerMetadataDraft14To11,
      zJwtVcJsonLdCredentialIssuerMetadataDraft14To11,
      // To handle unrecognized formats and not error immediately we allow the common format as well
      // but they can't use any of the format identifiers that have a specific transformation. This way if a format is
      // has a transformation it NEEDS to use the format specific transformation, and otherwise we fall back to the common validation
      z
        .object({
          format: z
            .string()
            .refine(
              (input) =>
                !(
                  [
                    zLdpVcFormatIdentifier.value,
                    zJwtVcJsonFormatIdentifier.value,
                    zJwtVcJsonLdFormatIdentifier.value,
                  ] as string[]
                ).includes(input)
            ),
        })
        .passthrough(),
    ])
  )

export const zCredentialIssuerMetadataDraft11To16 = z
  .object({
    authorization_server: z.string().optional(),
    credentials_supported: z.array(
      z
        .object({
          id: z.string().optional(),
        })
        .passthrough()
    ),
  })
  .passthrough()
  .transform(({ authorization_server, credentials_supported, ...rest }) => {
    return {
      ...rest,
      ...(authorization_server ? { authorization_servers: [authorization_server] } : {}),
      // Go from array to map but keep v11 structure
      credential_configurations_supported: Object.fromEntries(
        credentials_supported
          .map((supported) => (supported.id ? ([supported.id, supported] as const) : undefined))
          .filter((i): i is Exclude<typeof i, undefined> => i !== undefined)
      ),
    }
  })
  .pipe(
    z
      .object({
        // Update from v11 structure to v14 structure
        credential_configurations_supported: z.record(z.string(), zCredentialConfigurationSupportedDraft11To16),
      })
      .passthrough()
  )
  .pipe(zCredentialIssuerMetadataDraft14Draft15Draft16)

/**
 * Typing is a bit off on this one
 */
export type CredentialIssuerMetadataDraft11 = Simplify<
  CredentialIssuerMetadata & {
    authorization_server?: string
    credentials_supported: z.infer<typeof zCredentialConfigurationSupportedDraft16To11>[]
  }
>

export const zCredentialIssuerMetadataWithDraft11: z.ZodType<
  CredentialIssuerMetadataDraft11,
  z.ZodTypeDef,
  z.input<typeof zCredentialIssuerMetadataDraft14Draft15Draft16>
> = zCredentialIssuerMetadataDraft14Draft15Draft16
  .transform((issuerMetadata) => ({
    ...issuerMetadata,
    ...(issuerMetadata.authorization_servers ? { authorization_server: issuerMetadata.authorization_servers[0] } : {}),
    credentials_supported: Object.entries(issuerMetadata.credential_configurations_supported).map(([id, value]) => ({
      ...value,
      id,
    })),
  }))
  .pipe(
    zCredentialIssuerMetadataDraft14Draft15Draft16.extend({
      credentials_supported: z.array(zCredentialConfigurationSupportedDraft16To11),
    })
  )

export const zCredentialIssuerMetadata = z.union([
  // First prioritize draft 16/15/14 (and 13)
  zCredentialIssuerMetadataDraft14Draft15Draft16,
  // Then try parsing draft 11 and transform into draft 16
  zCredentialIssuerMetadataDraft11To16,
])

export const zCredentialIssuerMetadataWithDraftVersion = z.union([
  zCredentialIssuerMetadataDraft14Draft15Draft16.transform((credentialIssuerMetadata) => {
    const credentialConfigurations = Object.values(credentialIssuerMetadata.credential_configurations_supported)

    const isDraft15 = credentialConfigurations.some((configuration) => {
      const knownConfiguration = configuration as CredentialConfigurationSupportedWithFormats

      // Added in draft 15, it's not possible to detect with 100% guarantee
      if (knownConfiguration.format === zSdJwtDcFormatIdentifier.value) return true
      if (Array.isArray(knownConfiguration.claims)) return true
      if (
        Object.values(knownConfiguration.proof_types_supported ?? {}).some(
          (proofType) => proofType.key_attestations_required !== undefined
        )
      )
        return true

      // For now we assume draft 14 if we don't have any evidence it's draft 15
      return false
    })

    const isDraft16 = credentialConfigurations.some((configuration) => {
      // Added in draft 16
      return configuration.credential_metadata
    })

    return {
      credentialIssuerMetadata,
      originalDraftVersion: isDraft16
        ? Openid4vciDraftVersion.Draft16
        : isDraft15
          ? Openid4vciDraftVersion.Draft15
          : Openid4vciDraftVersion.Draft14,
    }
  }),
  // Then try parsing draft 11 and transform into draft 14
  zCredentialIssuerMetadataDraft11To16.transform((credentialIssuerMetadata) => ({
    credentialIssuerMetadata,
    originalDraftVersion: Openid4vciDraftVersion.Draft11,
  })),
])
