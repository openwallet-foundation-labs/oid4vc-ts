import * as v from 'valibot'

import type { InferOutputUnion } from '../common/validation/v-common'
import { vMsoMdocCredentialRequestFormat } from '../formats/credential/mso-mdoc/v-mso-mdoc'
import { vSdJwtVcCredentialRequestFormat } from '../formats/credential/sd-jwt-vc/v-sd-jwt-vc'
import {
  vJwtVcJsonLdCredentialRequestFormat,
  vLdpVcCredentialRequestFormat,
} from '../formats/credential/w3c-vc/v-w3c-vc-json-ld'
import { vJwtVcJsonCredentialRequestFormat } from '../formats/credential/w3c-vc/v-w3c-vc-jwt'
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
export type CredentialRequestFormats = InferOutputUnion<typeof allCredentialRequestFormats>

// Authorization details no format used
const vAuthorizationDetailsCredentialRequest = v.looseObject({
  credential_identifier: v.string(),

  // Cannot be present if credential identifier is present
  format: v.optional(v.undefined()),
})

export const vCredentialRequest = v.pipe(
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

// TODO: fix this type infer
export type CredentialRequest = v.InferOutput<typeof vCredentialRequest>
