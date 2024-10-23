import * as v from 'valibot'

import type { InferOutputUnion } from '../common/validation/v-common'
import {
  vJwtVcJsonCredentialRequestFormat,
  vJwtVcJsonLdCredentialRequestFormat,
  vLdpVcCredentialRequestFormat,
  vMsoMdocCredentialRequestFormat,
  vSdJwtVcCredentialRequestFormat,
} from '../formats/credential'
import {
  vJwtVcJsonCredentialRequestDraft11To14,
  vJwtVcJsonFormatIdentifier,
} from '../formats/credential/w3c-vc/v-w3c-jwt-vc-json'
import {
  vJwtVcJsonLdCredentialRequestDraft11To14,
  vJwtVcJsonLdFormatIdentifier,
} from '../formats/credential/w3c-vc/v-w3c-jwt-vc-json-ld'
import { vLdpVcCredentialRequestDraft11To14, vLdpVcFormatIdentifier } from '../formats/credential/w3c-vc/v-w3c-ldp-vc'
import { vCredentialRequestCommon } from './v-credential-request-common'

const allCredentialRequestFormats = [
  vSdJwtVcCredentialRequestFormat,
  vMsoMdocCredentialRequestFormat,
  vLdpVcCredentialRequestFormat,
  vJwtVcJsonLdCredentialRequestFormat,
  vJwtVcJsonCredentialRequestFormat,
] as const
const allCredentialRequestFormatIdentifiers = allCredentialRequestFormats.map(
  (format) => format.entries.format.literal
) as string[]

// Authorization details no format used
const vAuthorizationDetailsCredentialRequest = v.looseObject({
  credential_identifier: v.string(),

  // Cannot be present if credential identifier is present
  format: v.optional(v.undefined()),
})

const vCredentialRequestDraft14 = v.pipe(
  vCredentialRequestCommon,
  v.union([
    ...allCredentialRequestFormats,
    vAuthorizationDetailsCredentialRequest,

    // To handle unrecognized format values and not error immediately we allow the common format as well
    // but they can't use any of the format identifiers already registered. This way if a format is
    // recognized it NEEDS to use the format specific validation, and otherwise we fall back to the common validation
    v.looseObject({
      format: v.pipe(
        v.string(),
        v.check((input) => !allCredentialRequestFormatIdentifiers.includes(input))
      ),
    }),
  ])
)

const vCredentialRequestDraft11To14 = v.pipe(
  vCredentialRequestCommon,
  v.union([
    vLdpVcCredentialRequestDraft11To14,
    vJwtVcJsonLdCredentialRequestDraft11To14,
    vJwtVcJsonCredentialRequestDraft11To14,
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
  v.union(allCredentialRequestFormats)
)

export const vCredentialRequest = v.union([vCredentialRequestDraft14, vCredentialRequestDraft11To14])

export type CredentialRequestWithFormats = InferOutputUnion<typeof allCredentialRequestFormats>
export type CredentialRequest = v.InferOutput<typeof vCredentialRequestDraft14>

// We use a bit more complex type infer here, as format can be string so it removes all the type hinting
export type StrictCredentialRequest<Format> = Format extends CredentialRequestWithFormats['format']
  ? CredentialRequestWithFormats
  : CredentialRequest
