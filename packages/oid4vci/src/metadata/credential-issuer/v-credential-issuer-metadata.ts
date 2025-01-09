import { vCompactJwt } from '@openid4vc/oauth2'
import { type InferOutputUnion, type Simplify, vHttpsUrl } from '@openid4vc/utils'
import * as v from 'valibot'
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
  (format) => format.entries.format.literal
)

export const vCredentialConfigurationSupportedWithFormats = v.intersect([
  v.variant('format', [
    ...allCredentialIssuerMetadataFormats,

    // To handle unrecognized formats and not error immediately we allow the common format as well
    // but they can't use any of the foramt identifiers already regsitered. This way if a format is
    // recognized it NEEDS to use the format specific validation, and otherwise we fall back to the common validation
    v.looseObject({
      format: v.pipe(
        v.string(),
        v.check((input) => !allCredentialIssuerMetadataFormatIdentifiers.includes(input as CredentialFormatIdentifier))
      ),
    }),
  ]),
  vCredentialConfigurationSupportedCommon,
])
type CredentialConfigurationSupportedCommon = v.InferOutput<typeof vCredentialConfigurationSupportedCommon>
export type CredentialConfigurationSupportedFormatSpecific = InferOutputUnion<typeof allCredentialIssuerMetadataFormats>
export type CredentialConfigurationSupportedWithFormats = CredentialConfigurationSupportedFormatSpecific &
  CredentialConfigurationSupportedCommon
export type CredentialConfigurationsSupportedWithFormats = Record<string, CredentialConfigurationSupportedWithFormats>

export type CredentialConfigurationSupported = v.InferOutput<typeof vCredentialConfigurationSupportedWithFormats>
export type CredentialConfigurationsSupported = Record<string, CredentialConfigurationSupported>

/**
 * Typing is a bit off on this one
 */
export type CredentialIssuerMetadataDraft11 = Simplify<
  CredentialIssuerMetadata & v.InferOutput<typeof vCredentialIssuerMetadataWithDraft11>
>

const vCredentialIssuerMetadataDisplayEntry = v.looseObject({
  name: v.optional(v.string()),
  locale: v.optional(v.string()),
  logo: v.optional(
    v.looseObject({
      // FIXME: make required again, but need to support draft 11 first
      uri: v.optional(v.string()),
      alt_text: v.optional(v.string()),
    })
  ),
})
export type CredentialIssuerMetadataDisplayEntry = v.InferOutput<typeof vCredentialIssuerMetadataDisplayEntry>

export type CredentialIssuerMetadata = v.InferOutput<typeof vCredentialIssuerMetadataDraft14>
const vCredentialIssuerMetadataDraft14 = v.looseObject({
  credential_issuer: vHttpsUrl,
  authorization_servers: v.optional(v.array(vHttpsUrl)),
  credential_endpoint: vHttpsUrl,
  deferred_credential_endpoint: v.optional(vHttpsUrl),
  notification_endpoint: v.optional(vHttpsUrl),

  // Added after draft 14, but needed for proper
  nonce_endpoint: v.optional(vHttpsUrl),
  credential_response_encryption: v.optional(
    v.looseObject({
      alg_values_supported: v.array(v.string()),
      enc_values_supported: v.array(v.string()),
      encryption_required: v.boolean(),
    })
  ),
  batch_credential_issuance: v.optional(
    v.looseObject({
      batch_size: v.pipe(v.number(), v.integer()),
    })
  ),
  signed_metadata: v.optional(vCompactJwt),
  display: v.optional(v.array(vCredentialIssuerMetadataDisplayEntry)),
  credential_configurations_supported: v.record(v.string(), vCredentialConfigurationSupportedWithFormats),
})

// Transforms credential supported to credential configuration supported format
// Ignores unknown formats
export const vCredentialConfigurationSupportedDraft11To14 = v.pipe(
  v.looseObject({
    id: v.optional(v.string()),
    format: v.string(),
    cryptographic_suites_supported: v.optional(v.array(v.string())),
    display: v.optional(
      v.array(
        v.looseObject({
          logo: v.optional(
            v.looseObject({
              url: v.optional(v.pipe(v.string(), v.url())),
            })
          ),
          background_image: v.optional(
            v.looseObject({
              url: v.optional(v.pipe(v.string(), v.url())),
            })
          ),
        })
      )
    ),
  }),
  v.transform(({ cryptographic_suites_supported, display, id, ...rest }) => ({
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
                  logo: {
                    uri: logo.url,
                  },
                }
              : {}),

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
  })),
  v.variant('format', [
    vLdpVcCredentialIssuerMetadataDraft11To14,
    vJwtVcJsonCredentialIssuerMetadataDraft11To14,
    vJwtVcJsonLdCredentialIssuerMetadataDraft11To14,
    // To handle unrecognized formats and not error immediately we allow the common format as well
    // but they can't use any of the foramt identifiers that have a specific transformation. This way if a format is
    // has a transformation it NEEDS to use the format specific transformation, and otherwise we fall back to the common validation
    v.looseObject({
      format: v.pipe(
        v.string(),
        v.check(
          (input) =>
            !(
              [
                vLdpVcFormatIdentifier.literal,
                vJwtVcJsonFormatIdentifier.literal,
                vJwtVcJsonLdFormatIdentifier.literal,
              ] as string[]
            ).includes(input)
        )
      ),
    }),
  ]),
  vCredentialConfigurationSupportedWithFormats
)

// Transforms credential configuration supported to credentials_supported format
// Ignores unknown formats
const vCredentialConfigurationSupportedDraft14To11 = v.pipe(
  v.intersect([v.looseObject({ id: v.string() }), vCredentialConfigurationSupportedWithFormats]),
  v.transform(({ id, credential_signing_alg_values_supported, display, proof_types_supported, scope, ...rest }) => ({
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
  })),
  v.intersect([
    v.looseObject({ id: v.string() }),
    v.variant('format', [
      vLdpVcCredentialIssuerMetadataDraft14To11,
      vJwtVcJsonCredentialIssuerMetadataDraft14To11,
      vJwtVcJsonLdCredentialIssuerMetadataDraft14To11,
      // To handle unrecognized formats and not error immediately we allow the common format as well
      // but they can't use any of the foramt identifiers that have a specific transformation. This way if a format is
      // has a transformation it NEEDS to use the format specific transformation, and otherwise we fall back to the common validation
      v.looseObject({
        format: v.pipe(
          v.string(),
          v.check(
            (input) =>
              !(
                [
                  vLdpVcFormatIdentifier.literal,
                  vJwtVcJsonFormatIdentifier.literal,
                  vJwtVcJsonLdFormatIdentifier.literal,
                ] as string[]
              ).includes(input)
          )
        ),
      }),
    ]),
  ])
)

export const vCredentialIssuerMetadataDraft11To14 = v.pipe(
  v.looseObject({
    authorization_server: v.optional(v.string()),
    credentials_supported: v.array(
      v.looseObject({
        id: v.optional(v.string()),
      })
    ),
  }),
  v.transform(({ authorization_server, credentials_supported, ...rest }) => {
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
  }),
  v.looseObject({
    // Update from v11 structrue to v14 structure
    credential_configurations_supported: v.record(v.string(), vCredentialConfigurationSupportedDraft11To14),
  }),
  vCredentialIssuerMetadataDraft14
)

export const vCredentialIssuerMetadataWithDraft11 = v.pipe(
  vCredentialIssuerMetadataDraft14,

  v.transform((issuerMetadata) => ({
    ...issuerMetadata,
    ...(issuerMetadata.authorization_servers ? { authorization_server: issuerMetadata.authorization_servers[0] } : {}),
    credentials_supported: Object.entries(issuerMetadata.credential_configurations_supported).map(([id, value]) => ({
      ...value,
      id,
    })),
  })),
  v.intersect([
    vCredentialIssuerMetadataDraft14,
    v.looseObject({
      credentials_supported: v.array(vCredentialConfigurationSupportedDraft14To11),
    }),
  ])
)

export const vCredentialIssuerMetadata = v.union([
  // First prioritize draft 14 (and 13)
  vCredentialIssuerMetadataDraft14,
  // Then try parsing draft 11 and transform into draft 14
  vCredentialIssuerMetadataDraft11To14,
])

export const vCredentialIssuerMetadataWithDraftVersion = v.union([
  // First prioritize draft 14 (and 13)
  v.pipe(
    vCredentialIssuerMetadataDraft14,
    v.transform((credentialIssuerMetadata) => ({
      credentialIssuerMetadata,
      originalDraftVersion: Oid4vciDraftVersion.Draft14,
    }))
  ),
  // Then try parsing draft 11 and transform into draft 14
  v.pipe(
    vCredentialIssuerMetadataDraft11To14,
    v.transform((credentialIssuerMetadata) => ({
      credentialIssuerMetadata,
      originalDraftVersion: Oid4vciDraftVersion.Draft11,
    }))
  ),
])
