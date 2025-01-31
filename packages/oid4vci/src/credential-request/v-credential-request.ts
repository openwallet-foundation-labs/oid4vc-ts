import type { InferOutputUnion, Simplify } from '@openid4vc/utils'
import z from 'zod'
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
  (format) => format.shape.format.value
)

// Authorization details no format used
const vAuthorizationDetailsCredentialRequest = z.object({
  credential_identifier: z.string(),

  // Cannot be present if credential identifier is present
  format: z.never({ message: "'format' cannot be defined when 'credential_identifier' is set." }).optional(),
})

const zCredentialRequestFormatNoCredentialIdentifier = z
  .object({
    format: z.string(),
    credential_identifier: z
      .never({ message: "'credential_identifier' cannot be defined when 'format' is set." })
      .optional(),
  })
  .passthrough()

export const vCredenialRequestDraft14WithFormat = vCredentialRequestCommon
  .and(zCredentialRequestFormatNoCredentialIdentifier)
  .transform((data, ctx) => {
    // No additional validation for unknown formats
    if (!allCredentialRequestFormatIdentifiers.includes(data.format as CredentialFormatIdentifier)) return data

    const result = z
      // We use object and passthrough as otherwise the non-format specific properties will be stripped
      .object({})
      .passthrough()
      .and(z.discriminatedUnion('format', allCredentialRequestFormats))
      .safeParse(data)
    if (result.success) {
      return result.data as Simplify<typeof result.data & typeof data>
    }
    for (const issue of result.error.issues) {
      ctx.addIssue(issue)
    }
    return z.NEVER
  })

const vCredentialRequestDraft14 = z.union([
  vCredenialRequestDraft14WithFormat,
  vCredentialRequestCommon.and(vAuthorizationDetailsCredentialRequest),
])

export const vCredentialRequestDraft11To14 = vCredentialRequestCommon
  .and(zCredentialRequestFormatNoCredentialIdentifier)
  .transform((data, ctx) => {
    const formatSpecificTransformations = {
      [vLdpVcFormatIdentifier.value]: vLdpVcCredentialRequestDraft11To14,
      [vJwtVcJsonFormatIdentifier.value]: vJwtVcJsonCredentialRequestDraft11To14,
      [vJwtVcJsonLdFormatIdentifier.value]: vJwtVcJsonLdCredentialRequestDraft11To14,
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
  .pipe(vCredentialRequestDraft14)

export const vCredentialRequestDraft14To11 = vCredentialRequestDraft14
  .refine(
    (data): data is Exclude<typeof data, { credential_identifier: string }> => data.credential_identifier === undefined,
    `'credential_identifier' is not supported in OID4VCI draft 11`
  )
  .transform((data, ctx) => {
    const formatSpecificTransformations = {
      [vLdpVcFormatIdentifier.value]: vLdpVcCredentialRequestDraft14To11,
      [vJwtVcJsonFormatIdentifier.value]: vJwtVcJsonLdCredentialRequestDraft14To11,
      [vJwtVcJsonLdFormatIdentifier.value]: vJwtVcJsonCredentialRequestDraft14To11,
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

export const vCredentialRequest = z.union([vCredentialRequestDraft14, vCredentialRequestDraft11To14])

type CredentialRequestCommon = z.infer<typeof vCredentialRequestCommon>
export type CredentialRequestFormatSpecific = InferOutputUnion<typeof allCredentialRequestFormats>
export type CredentialRequestWithFormats = CredentialRequestCommon & CredentialRequestFormatSpecific

export type CredentialRequest = z.infer<typeof vCredentialRequestDraft14>
