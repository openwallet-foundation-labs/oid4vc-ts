import { vCompactJwt } from '@openid4vc/oauth2'
import { type InferOutputUnion, type Simplify, vHttpsUrl } from '@openid4vc/utils'
import z from 'zod'
import {
  type CredentialFormatIdentifier,
  vJwtVcJsonCredentialIssuerMetadata,
  vJwtVcJsonCredentialIssuerMetadataDraft11To14,
  vJwtVcJsonCredentialIssuerMetadataDraft14To11,
  vJwtVcJsonFormatIdentifier,
  vJwtVcJsonLdCredentialIssuerMetadata,
  vJwtVcJsonLdCredentialIssuerMetadataDraft11To14,
  vJwtVcJsonLdCredentialIssuerMetadataDraft14To11,
  vJwtVcJsonLdFormatIdentifier,
  vLdpVcCredentialIssuerMetadata,
  vLdpVcCredentialIssuerMetadataDraft11To14,
  vLdpVcCredentialIssuerMetadataDraft14To11,
  vLdpVcFormatIdentifier,
  vMsoMdocCredentialIssuerMetadata,
  vSdJwtVcCredentialIssuerMetadata,
} from '../../formats/credential'
import { Oid4vciDraftVersion } from '../../version'
import { vCredentialConfigurationSupportedCommon } from './v-credential-configuration-supported-common'

const allCredentialIssuerMetadataFormats = [
  vSdJwtVcCredentialIssuerMetadata,
  vMsoMdocCredentialIssuerMetadata,
  vJwtVcJsonLdCredentialIssuerMetadata,
  vLdpVcCredentialIssuerMetadata,
  vJwtVcJsonCredentialIssuerMetadata,
] as const
export const allCredentialIssuerMetadataFormatIdentifiers = allCredentialIssuerMetadataFormats.map(
  (format) => format.shape.format.value
)

export const vCredentialConfigurationSupportedWithFormats = vCredentialConfigurationSupportedCommon.transform(
  (data, ctx) => {
    // No additional validation for unknown formats
    if (!allCredentialIssuerMetadataFormatIdentifiers.includes(data.format as CredentialFormatIdentifier)) return data

    const result = z
      // We use object and passthrough as otherwise the non-format specific properties will be stripped
      .object({})
      .passthrough()
      .and(z.discriminatedUnion('format', allCredentialIssuerMetadataFormats))
      .safeParse(data)
    if (result.success) {
      return result.data as Simplify<typeof result.data & typeof data>
    }
    for (const issue of result.error.issues) {
      ctx.addIssue(issue)
    }
    return z.NEVER
  }
)

type CredentialConfigurationSupportedCommon = z.infer<typeof vCredentialConfigurationSupportedCommon>
export type CredentialConfigurationSupportedFormatSpecific = InferOutputUnion<typeof allCredentialIssuerMetadataFormats>
export type CredentialConfigurationSupportedWithFormats = CredentialConfigurationSupportedFormatSpecific &
  CredentialConfigurationSupportedCommon
export type CredentialConfigurationsSupportedWithFormats = Record<string, CredentialConfigurationSupportedWithFormats>

export type CredentialConfigurationSupported = z.infer<typeof vCredentialConfigurationSupportedWithFormats>
export type CredentialConfigurationsSupported = Record<string, CredentialConfigurationSupported>

/**
 * Typing is a bit off on this one
 */
export type CredentialIssuerMetadataDraft11 = Simplify<
  CredentialIssuerMetadata & z.infer<typeof vCredentialIssuerMetadataWithDraft11>
>

const vCredentialIssuerMetadataDisplayEntry = z
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
export type CredentialIssuerMetadataDisplayEntry = z.infer<typeof vCredentialIssuerMetadataDisplayEntry>

export type CredentialIssuerMetadata = z.infer<typeof vCredentialIssuerMetadataDraft14>
const vCredentialIssuerMetadataDraft14 = z
  .object({
    credential_issuer: vHttpsUrl,
    authorization_servers: z.array(vHttpsUrl).optional(),
    credential_endpoint: vHttpsUrl,
    deferred_credential_endpoint: vHttpsUrl.optional(),
    notification_endpoint: vHttpsUrl.optional(),

    // Added after draft 14, but needed for proper
    nonce_endpoint: vHttpsUrl.optional(),
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
    signed_metadata: vCompactJwt.optional(),
    display: z.array(vCredentialIssuerMetadataDisplayEntry).optional(),
    credential_configurations_supported: z.record(z.string(), vCredentialConfigurationSupportedWithFormats),
  })
  .passthrough()

// Transforms credential supported to credential configuration supported format
// Ignores unknown formats
export const vCredentialConfigurationSupportedDraft11To14 = z
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
  })
  .passthrough()
  .transform(({ cryptographic_suites_supported, display, id, ...rest }) => ({
    ...rest,
    ...(cryptographic_suites_supported
      ? { credential_signing_alg_values_supported: cryptographic_suites_supported }
      : {}),
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
  }))
  .transform((data, ctx) => {
    const formatSpecificTransformations = {
      [vLdpVcFormatIdentifier.value]: vLdpVcCredentialIssuerMetadataDraft11To14,
      [vJwtVcJsonFormatIdentifier.value]: vJwtVcJsonCredentialIssuerMetadataDraft11To14,
      [vJwtVcJsonLdFormatIdentifier.value]: vJwtVcJsonLdCredentialIssuerMetadataDraft11To14,
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
  .pipe(vCredentialConfigurationSupportedWithFormats)

// Transforms credential configuration supported to credentials_supported format
// Ignores unknown formats
const vCredentialConfigurationSupportedDraft14To11 = vCredentialConfigurationSupportedWithFormats
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
      vLdpVcCredentialIssuerMetadataDraft14To11,
      vJwtVcJsonCredentialIssuerMetadataDraft14To11,
      vJwtVcJsonLdCredentialIssuerMetadataDraft14To11,
      // To handle unrecognized formats and not error immediately we allow the common format as well
      // but they can't use any of the foramt identifiers that have a specific transformation. This way if a format is
      // has a transformation it NEEDS to use the format specific transformation, and otherwise we fall back to the common validation
      z
        .object({
          format: z
            .string()
            .refine(
              (input) =>
                !(
                  [
                    vLdpVcFormatIdentifier.value,
                    vJwtVcJsonFormatIdentifier.value,
                    vJwtVcJsonLdFormatIdentifier.value,
                  ] as string[]
                ).includes(input)
            ),
        })
        .passthrough(),
    ])
  )

export const vCredentialIssuerMetadataDraft11To14 = z
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
        // Update from v11 structrue to v14 structure
        credential_configurations_supported: z.record(z.string(), vCredentialConfigurationSupportedDraft11To14),
      })
      .passthrough()
  )
  .pipe(vCredentialIssuerMetadataDraft14)

export const vCredentialIssuerMetadataWithDraft11 = vCredentialIssuerMetadataDraft14
  .transform((issuerMetadata) => ({
    ...issuerMetadata,
    ...(issuerMetadata.authorization_servers ? { authorization_server: issuerMetadata.authorization_servers[0] } : {}),
    credentials_supported: Object.entries(issuerMetadata.credential_configurations_supported).map(([id, value]) => ({
      ...value,
      id,
    })),
  }))
  .pipe(
    vCredentialIssuerMetadataDraft14.extend({
      credentials_supported: z.array(vCredentialConfigurationSupportedDraft14To11),
    })
  )

export const vCredentialIssuerMetadata = z.union([
  // First prioritize draft 14 (and 13)
  vCredentialIssuerMetadataDraft14,
  // Then try parsing draft 11 and transform into draft 14
  vCredentialIssuerMetadataDraft11To14,
])

export const vCredentialIssuerMetadataWithDraftVersion = z.union([
  // First prioritize draft 14 (and 13)

  vCredentialIssuerMetadataDraft14.transform((credentialIssuerMetadata) => ({
    credentialIssuerMetadata,
    originalDraftVersion: Oid4vciDraftVersion.Draft14,
  })),
  // Then try parsing draft 11 and transform into draft 14
  vCredentialIssuerMetadataDraft11To14.transform((credentialIssuerMetadata) => ({
    credentialIssuerMetadata,
    originalDraftVersion: Oid4vciDraftVersion.Draft11,
  })),
])
