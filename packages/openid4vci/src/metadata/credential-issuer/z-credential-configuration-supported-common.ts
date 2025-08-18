import z from 'zod'
import { zIso18045OrStringArray } from '../../key-attestation/z-key-attestation'

const zCredentialConfigurationSupportedDisplayEntry = z
  .object({
    name: z.string(),
    locale: z.string().optional(),
    logo: z
      .object({
        // FIXME: make required again, but need to support draft 11 first
        uri: z.string().optional(),
        alt_text: z.string().optional(),
      })
      .passthrough()
      .optional(),
    description: z.string().optional(),
    background_color: z.string().optional(),
    background_image: z
      .object({
        // TODO: should be required, but paradym's metadata is wrong here.
        uri: z.string().optional(),
      })
      .passthrough()
      .optional(),
    text_color: z.string().optional(),
  })
  .passthrough()

export const zCredentialConfigurationSupportedCommonCredentialMetadata = z.object({
  display: z.array(zCredentialConfigurationSupportedDisplayEntry).optional(),
})

export const zCredentialConfigurationSupportedCommon = z.object({
  format: z.string(),
  scope: z.string().optional(),
  cryptographic_binding_methods_supported: z.array(z.string()).optional(),
  credential_signing_alg_values_supported: z.array(z.string()).or(z.array(z.number())).optional(),
  proof_types_supported: z
    .record(
      z.union([z.literal('jwt'), z.literal('attestation'), z.string()]),
      z.object({
        proof_signing_alg_values_supported: z.array(z.string()),
        key_attestations_required: z
          .object({
            key_storage: zIso18045OrStringArray.optional(),
            user_authentication: zIso18045OrStringArray.optional(),
          })
          .passthrough()
          .optional(),
      })
    )
    .optional(),
  credential_metadata: zCredentialConfigurationSupportedCommonCredentialMetadata.optional(),

  // For typing purposes. Can be removed once we drop support for draft <= 15.
  claims: z.optional(z.never()),
})

export const zCredentialConfigurationSupportedCommonDraft15 = z.object({
  format: z.string(),
  scope: z.string().optional(),
  cryptographic_binding_methods_supported: z.array(z.string()).optional(),
  credential_signing_alg_values_supported: z.array(z.string()).or(z.array(z.number())).optional(),
  proof_types_supported: z
    .record(
      z.union([z.literal('jwt'), z.literal('attestation'), z.string()]),
      z.object({
        proof_signing_alg_values_supported: z.array(z.string()),
        key_attestations_required: z
          .object({
            key_storage: zIso18045OrStringArray.optional(),
            user_authentication: zIso18045OrStringArray.optional(),
          })
          .passthrough()
          .optional(),
      })
    )
    .optional(),
  display: z.array(zCredentialConfigurationSupportedDisplayEntry).optional(),

  // For typing purposes.
  credential_metadata: z.optional(z.never()),
})
