import * as v from 'valibot'

export const vCredentialConfigurationSupportedClaims = v.looseObject({
  mandatory: v.optional(v.boolean()),
  value_type: v.optional(v.string()),
  display: v.optional(
    v.looseObject({
      name: v.optional(v.string()),
      locale: v.optional(v.string()),
    })
  ),
})

export const vCredentialConfigurationSupportedCommon = v.looseObject({
  format: v.string(),
  scope: v.optional(v.string()),
  cryptographic_binding_methods_supported: v.optional(v.array(v.string())),
  credential_signing_alg_values_supported: v.optional(v.array(v.string())),
  proof_types_supported: v.optional(
    v.record(
      v.union([v.literal('jwt'), v.string()]),
      v.object({
        proof_signing_alg_values_supported: v.array(v.string()),
      })
    )
  ),
  display: v.optional(
    v.array(
      v.looseObject({
        name: v.string(),
        locale: v.optional(v.string()),
        logo: v.optional(
          v.looseObject({
            // FIXME: make required again, but need to support draft 11 first
            uri: v.optional(v.string()),
            alt_text: v.optional(v.string()),
          })
        ),
        description: v.optional(v.string()),
        background_color: v.optional(v.string()),
        background_image: v.optional(
          v.looseObject({
            // TODO: should be required, but paradym's metadata is wrong here.
            uri: v.optional(v.string()),
          })
        ),
        text_color: v.optional(v.string()),
      })
    )
  ),
})
