import * as v from 'valibot'

import type { InferOutputUnion } from '@animo-id/oid4vc-utils'
import {
  type CredentialFormatIdentifier,
  vJwtVcJsonCredentialRequestFormat,
  vJwtVcJsonLdCredentialRequestFormat,
  vLdpVcCredentialRequestFormat,
  vMsoMdocCredentialRequestFormat,
  vSdJwtVcCredentialRequestFormat,
} from '../formats/credential'
import {
  vJwtVcJsonCredentialRequestDraft11To14,
  vJwtVcJsonCredentialRequestDraft14To11,
  vJwtVcJsonFormatIdentifier,
} from '../formats/credential/w3c-vc/v-w3c-jwt-vc-json'
import {
  vJwtVcJsonLdCredentialRequestDraft11To14,
  vJwtVcJsonLdCredentialRequestDraft14To11,
  vJwtVcJsonLdFormatIdentifier,
} from '../formats/credential/w3c-vc/v-w3c-jwt-vc-json-ld'
import {
  vLdpVcCredentialRequestDraft11To14,
  vLdpVcCredentialRequestDraft14To11,
  vLdpVcFormatIdentifier,
} from '../formats/credential/w3c-vc/v-w3c-ldp-vc'
import { vCredentialRequestCommon } from './v-credential-request-common'

export const allCredentialRequestFormats = [
  vSdJwtVcCredentialRequestFormat,
  vMsoMdocCredentialRequestFormat,
  vLdpVcCredentialRequestFormat,
  vJwtVcJsonLdCredentialRequestFormat,
  vJwtVcJsonCredentialRequestFormat,
] as const

export const allCredentialRequestFormatIdentifiers = allCredentialRequestFormats.map(
  (format) => format.entries.format.literal
)

// Authorization details no format used
const vAuthorizationDetailsCredentialRequest = v.object({
  credential_identifier: v.string(),

  // Cannot be present if credential identifier is present
  format: v.optional(v.never("'format' cannot be defined when 'credential_identifier' is set.")),
})

const vCredenialRequestDraft14WithFormat = v.intersect([
  vCredentialRequestCommon,
  v.union([
    ...allCredentialRequestFormats,
    // To handle unrecognized format values and not error immediately we allow the common format as well
    // but they can't use any of the format identifiers already registered. This way if a format is
    // recognized it NEEDS to use the format specific validation, and otherwise we fall back to the common validation
    v.looseObject({
      format: v.pipe(
        v.string(),
        v.check((input) => !allCredentialRequestFormatIdentifiers.includes(input as CredentialFormatIdentifier))
      ),
    }),
  ]),
  v.object({
    credential_identifier: v.optional(v.never("'credential_identifier' cannot be defined when 'format' is set.")),
  }),
])

const vCredentialRequestDraft14 = v.union([
  vCredenialRequestDraft14WithFormat,
  v.intersect([vCredentialRequestCommon, vAuthorizationDetailsCredentialRequest]),
])

export const vCredentialRequestDraft11To14 = v.pipe(
  vCredentialRequestCommon,
  v.intersect([
    v.union([
      vLdpVcCredentialRequestDraft11To14,
      vJwtVcJsonLdCredentialRequestDraft11To14,
      vJwtVcJsonCredentialRequestDraft11To14,
    ]),
    v.object({
      credential_identifier: v.optional(v.never("'credential_identifier' cannot be defined when 'format' is set.")),
    }),
  ]),
  // Same as draft 14 but only for above used formats
  v.intersect([
    vCredentialRequestCommon,
    v.union([vLdpVcCredentialRequestFormat, vJwtVcJsonLdCredentialRequestFormat, vJwtVcJsonCredentialRequestFormat]),
    v.object({
      credential_identifier: v.optional(v.never("'credential_identifier' cannot be defined when 'format' is set.")),
    }),
  ])
)

export const vCredentialRequestDraft14To11 = v.pipe(
  vCredentialRequestDraft14,
  v.check(
    ({ credential_identifier }) => credential_identifier === undefined,
    `'credential_identifier' is not supported in OID4VCI draft 11`
  ),

  v.union([
    vLdpVcCredentialRequestDraft14To11,
    vJwtVcJsonLdCredentialRequestDraft14To11,
    vJwtVcJsonCredentialRequestDraft14To11,
    // To handle unrecognized format values and not error immediately we allow the common format as well
    // but they can't use any of the format identifiers already registered. This way if a format is
    // recognized it NEEDS to use the format specific validation, and otherwise we fall back to the common validation
    v.looseObject({
      format: v.pipe(
        v.string(),
        v.check(
          (input) =>
            !(
              [
                vJwtVcJsonFormatIdentifier.literal,
                vJwtVcJsonLdFormatIdentifier.literal,
                vLdpVcFormatIdentifier.literal,
              ] as string[]
            ).includes(input)
        )
      ),
    }),
  ])
)

export const vCredentialRequest = v.union([vCredentialRequestDraft14, vCredentialRequestDraft11To14])

type CredentialRequestCommon = v.InferOutput<typeof vCredentialRequestCommon>
export type CredentialRequestFormatSpecific = InferOutputUnion<typeof allCredentialRequestFormats>
export type CredentialRequestWithFormats = CredentialRequestCommon & CredentialRequestFormatSpecific

export type CredentialRequest = v.InferOutput<typeof vCredentialRequestDraft14>
