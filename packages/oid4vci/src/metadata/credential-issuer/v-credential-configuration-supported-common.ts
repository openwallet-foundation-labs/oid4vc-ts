import z from 'zod'
import { vIso18045OrStringArray } from '../../key-attestation/v-key-attestation'

export const vCredentialConfigurationSupportedClaims = z
  .object({
    mandatory: z.boolean().optional(),
    value_type: z.string().optional(),
    display: z
      .object({
        name: z.string().optional(),
        locale: z.string().optional(),
      })
      .passthrough()
      .optional(),
  })
  .passthrough()

export const vCredentialConfigurationSupportedCommon = z
  .object({
    format: z.string(),
    scope: z.string().optional(),
    cryptographic_binding_methods_supported: z.array(z.string()).optional(),
    credential_signing_alg_values_supported: z.array(z.string()).optional(),
    proof_types_supported: z
      .record(
        z.union([z.literal('jwt'), z.literal('attestation'), z.string()]),
        z.object({
          proof_signing_alg_values_supported: z.array(z.string()),
          key_attestations_required: z
            .object({
              key_storage: vIso18045OrStringArray.optional(),
              user_authentication: vIso18045OrStringArray.optional(),
            })
            .passthrough()
            .optional(),
        })
      )
      .optional(),
    display: z
      .array(
        z
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
      )
      .optional(),
  })
  .passthrough()
