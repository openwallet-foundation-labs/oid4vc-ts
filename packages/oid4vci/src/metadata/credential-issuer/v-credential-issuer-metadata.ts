import * as v from 'valibot'
import { vCompactJwt, vHttpsUrl } from '../../common/validation/v-common'
import { vMsoMdocCredentialIssuerMetadata } from '../../formats/credential/mso-mdoc/v-mso-mdoc'
import { vSdJwtVcCredentialIssuerMetadata } from '../../formats/credential/sd-jwt-vc/v-sd-jwt-vc'
import {
  vJwtVcJsonLdCredentialIssuerMetadata,
  vLdpVcCredentialIssuerMetadata,
} from '../../formats/credential/w3c-vc/v-w3c-vc-json-ld'
import { vJwtVcJsonCredentialIssuerMetadata } from '../../formats/credential/w3c-vc/v-w3c-vc-jwt'
import { vAuthorizationServerIdentifier } from '../authorization-server/v-authorization-server-metadata'
import { vCredentialConfigurationSupportedCommon } from './v-credential-configuration-supported-common'

export const vCredentialIssuerIdentifier = vHttpsUrl

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

export const vCredentialConfigurationSupportedWithFormats = v.variant('format', [
  ...allCredentialIssuerMetadataFormats,

  // To handle unrecognized formats and not error immediately we allow the common format as well
  // but they can't use any of the foramt identifiers already regsitered. This way if a format is
  // recognized it NEEDS to use the format specific validation, and otherwise we fall back to the common validation
  v.looseObject({
    ...vCredentialConfigurationSupportedCommon.entries,
    format: v.pipe(
      v.string(),
      v.custom<string>(
        (input) => typeof input === 'string' && !allCredentialIssuerMetadataFormatIdentifiers.includes(input)
      )
    ),
  }),
])

export type CredentialIssuerMetadata = v.InferOutput<typeof vCredentialIssuerMetadata>
export const vCredentialIssuerMetadata = v.looseObject({
  credential_issuer: vCredentialIssuerIdentifier,
  authorization_servers: v.optional(v.array(vAuthorizationServerIdentifier)),
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
