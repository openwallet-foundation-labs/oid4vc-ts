import { z } from 'zod'

export const zVpFormatsSupported = z
  // Define known formats
  .object({
    'dc+sd-jwt': z.optional(
      z
        .object({
          'sd-jwt_alg_values': z.optional(z.array(z.string()).nonempty()),
          'kb-jwt_alg_values': z.optional(z.array(z.string()).nonempty()),
        })
        .passthrough()
    ),
    jwt_vc_json: z.optional(
      z
        .object({
          alg_values: z.optional(z.array(z.string()).nonempty()),
        })
        .passthrough()
    ),
    ldp_vc: z.optional(
      z
        .object({
          proof_type_values: z.optional(z.array(z.string()).nonempty()),
          cryptosuite_values: z.optional(z.array(z.string()).nonempty()),
        })
        .passthrough()
    ),
    mso_mdoc: z.optional(
      z
        .object({
          // Draft 27
          issuer_signed_alg_values: z.optional(z.array(z.number()).nonempty()),
          device_signed_alg_values: z.optional(z.array(z.number()).nonempty()),

          // Draft 28+
          issuerauth_alg_values: z.optional(z.array(z.number()).nonempty()),
          deviceauth_alg_values: z.optional(z.array(z.number()).nonempty()),
        })
        .passthrough()
    ),
  })
  .passthrough()
  // Require object for all unknown formats
  .catchall(z.object({}).passthrough())

export type VpFormatsSupported = z.infer<typeof zVpFormatsSupported>

export const zLegacyVpFormats = z.record(
  z.string(),
  z
    .object({
      alg_values_supported: z.optional(z.array(z.string())),
    })
    .passthrough()
)

export type LegacyVpFormats = z.infer<typeof zLegacyVpFormats>
