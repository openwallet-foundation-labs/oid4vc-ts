import type { InferOutputUnion, Simplify } from '@openid4vc/utils'
import z from 'zod'
import {
  type CredentialFormatIdentifier,
  zJwtVcJsonCredentialRequestFormat,
  zJwtVcJsonLdCredentialRequestFormat,
  zLdpVcCredentialRequestFormat,
  zMsoMdocCredentialRequestFormat,
  zSdJwtVcCredentialRequestFormat,
} from '../formats/credential'
import {
  zJwtVcJsonCredentialRequestDraft11To14,
  zJwtVcJsonCredentialRequestDraft14To11,
  zJwtVcJsonFormatIdentifier,
} from '../formats/credential/w3c-vc/z-w3c-jwt-vc-json'
import {
  zJwtVcJsonLdCredentialRequestDraft11To14,
  zJwtVcJsonLdCredentialRequestDraft14To11,
  zJwtVcJsonLdFormatIdentifier,
} from '../formats/credential/w3c-vc/z-w3c-jwt-vc-json-ld'
import {
  zLdpVcCredentialRequestDraft11To14,
  zLdpVcCredentialRequestDraft14To11,
  zLdpVcFormatIdentifier,
} from '../formats/credential/w3c-vc/z-w3c-ldp-vc'
import { zCredentialRequestCommon } from './z-credential-request-common'

export const allCredentialRequestFormats = [
  zSdJwtVcCredentialRequestFormat,
  zMsoMdocCredentialRequestFormat,
  zLdpVcCredentialRequestFormat,
  zJwtVcJsonLdCredentialRequestFormat,
  zJwtVcJsonCredentialRequestFormat,
] as const

export const allCredentialRequestFormatIdentifiers = allCredentialRequestFormats.map(
  (format) => format.shape.format.value
)

// Authorization details no format used
const zAuthorizationDetailsCredentialRequest = z.object({
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

export const zCredenialRequestDraft14WithFormat = zCredentialRequestCommon
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

const zCredentialRequestDraft14 = z.union([
  zCredenialRequestDraft14WithFormat,
  zCredentialRequestCommon.and(zAuthorizationDetailsCredentialRequest),
])

export const zCredentialRequestDraft11To14 = zCredentialRequestCommon
  .and(zCredentialRequestFormatNoCredentialIdentifier)
  .transform((data, ctx) => {
    const formatSpecificTransformations = {
      [zLdpVcFormatIdentifier.value]: zLdpVcCredentialRequestDraft11To14,
      [zJwtVcJsonFormatIdentifier.value]: zJwtVcJsonCredentialRequestDraft11To14,
      [zJwtVcJsonLdFormatIdentifier.value]: zJwtVcJsonLdCredentialRequestDraft11To14,
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
  .pipe(zCredentialRequestDraft14)

export const zCredentialRequestDraft14To11 = zCredentialRequestDraft14
  .refine(
    (data): data is Exclude<typeof data, { credential_identifier: string }> => data.credential_identifier === undefined,
    `'credential_identifier' is not supported in OID4VCI draft 11`
  )
  .transform((data, ctx) => {
    const formatSpecificTransformations = {
      [zLdpVcFormatIdentifier.value]: zLdpVcCredentialRequestDraft14To11,
      [zJwtVcJsonFormatIdentifier.value]: zJwtVcJsonCredentialRequestDraft14To11,
      [zJwtVcJsonLdFormatIdentifier.value]: zJwtVcJsonLdCredentialRequestDraft14To11,
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

export const zCredentialRequest = z.union([zCredentialRequestDraft14, zCredentialRequestDraft11To14])

type CredentialRequestCommon = z.infer<typeof zCredentialRequestCommon>
export type CredentialRequestFormatSpecific = InferOutputUnion<typeof allCredentialRequestFormats>
export type CredentialRequestWithFormats = CredentialRequestCommon & CredentialRequestFormatSpecific

export type CredentialRequest = z.infer<typeof zCredentialRequestDraft14>
