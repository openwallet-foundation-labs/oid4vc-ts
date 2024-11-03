import { vCompactJwt } from '@animo-id/oauth2'
import { type InferOutputUnion, vHttpsUrl } from '@animo-id/oid4vc-utils'
import * as v from 'valibot'
import {
  vJwtVcJsonCredentialIssuerMetadata,
  vJwtVcJsonCredentialIssuerMetadataDraft11To14,
  vJwtVcJsonFormatIdentifier,
  vJwtVcJsonLdCredentialIssuerMetadata,
  vJwtVcJsonLdCredentialIssuerMetadataDraft11To14,
  vJwtVcJsonLdFormatIdentifier,
  vLdpVcCredentialIssuerMetadata,
  vLdpVcCredentialIssuerMetadataDraft11To14,
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
const allCredentialIssuerMetadataFormatIdentifiers = allCredentialIssuerMetadataFormats.map(
  (format) => format.entries.format.literal
) as string[]

export const vCredentialConfigurationSupportedWithFormats = v.pipe(
  v.variant('format', [
    ...allCredentialIssuerMetadataFormats,

    // To handle unrecognized formats and not error immediately we allow the common format as well
    // but they can't use any of the foramt identifiers already regsitered. This way if a format is
    // recognized it NEEDS to use the format specific validation, and otherwise we fall back to the common validation
    v.looseObject({
      format: v.pipe(
        v.string(),
        v.check((input) => !allCredentialIssuerMetadataFormatIdentifiers.includes(input))
      ),
    }),
  ]),
  vCredentialConfigurationSupportedCommon
)
export type CredentialConfigurationSupportedWithFormat = InferOutputUnion<typeof allCredentialIssuerMetadataFormats>
export type CredentialConfigurationSupported = v.InferOutput<typeof vCredentialConfigurationSupportedWithFormats>
export type StrictCredentialConfigurationSupported<T extends { format: string }> =
  T['format'] extends CredentialConfigurationSupportedWithFormat['format']
    ? CredentialConfigurationSupportedWithFormat & T
    : CredentialConfigurationSupported

export type CredentialIssuerMetadata = v.InferOutput<typeof vCredentialIssuerMetadataDraft14>
const vCredentialIssuerMetadataDraft14 = v.looseObject({
  credential_issuer: vHttpsUrl,
  authorization_servers: v.optional(v.array(vHttpsUrl)),
  credential_endpoint: vHttpsUrl,
  deferred_credential_endpoint: v.optional(vHttpsUrl),
  notification_endpoint: v.optional(vHttpsUrl),
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
  display: v.optional(
    v.array(
      v.looseObject({
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
    )
  ),
  credential_configurations_supported: v.record(v.string(), vCredentialConfigurationSupportedWithFormats),
})

// Transforms credential supported to credential configuration supported format
// Ignores unknown formats
const vCredentialConfigurationSupportedDraft11To14 = v.pipe(
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
