import { z } from 'zod'

export const zVpFormatsSupported = z
  // Define known formats
  .object({
    'dc+sd-jwt': z.optional(
      z
        .object({
          'sd-jwt_alg_values': z.optional(z.tuple([z.string()], z.string())),
          'kb-jwt_alg_values': z.optional(z.tuple([z.string()], z.string())),
        })
        .loose()
    ),
    jwt_vc_json: z.optional(
      z
        .object({
          alg_values: z.optional(z.tuple([z.string()], z.string())),
        })
        .loose()
    ),
    ldp_vc: z.optional(
      z
        .object({
          proof_type_values: z.optional(z.tuple([z.string()], z.string())),
          cryptosuite_values: z.optional(z.tuple([z.string()], z.string())),
        })
        .loose()
    ),
    mso_mdoc: z.optional(
      z
        .object({
          // Draft 27
          issuer_signed_alg_values: z.optional(z.tuple([z.number()], z.number())),
          device_signed_alg_values: z.optional(z.tuple([z.number()], z.number())),

          // Draft 28+
          issuerauth_alg_values: z.optional(z.tuple([z.number()], z.number())),
          deviceauth_alg_values: z.optional(z.tuple([z.number()], z.number())),
        })
        .loose()
    ),
  })
  .loose()
  // Require object for all unknown formats
  .catchall(z.object({}).loose())

export type VpFormatsSupported = z.infer<typeof zVpFormatsSupported>

export const zLegacyVpFormats = z.record(
  z.string(),
  z
    .object({
      alg_values_supported: z.optional(z.array(z.string())),
    })
    .loose()
)

export type LegacyVpFormats = z.infer<typeof zLegacyVpFormats>
