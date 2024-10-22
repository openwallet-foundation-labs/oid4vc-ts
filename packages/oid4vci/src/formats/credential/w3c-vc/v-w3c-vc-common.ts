import * as v from 'valibot'

const vCredentialSubjectLeafType = v.looseObject({
  mandatory: v.optional(v.boolean(), false),
  value_type: v.optional(v.string()),
  display: v.optional(
    v.array(
      v.looseObject({
        name: v.optional(v.string()),
        locale: v.optional(v.string()),
      })
    )
  ),
})

// TODO: fix this type, having issues with recursiveness
const vClaimValueSchema = v.union([v.array(v.any()), v.record(v.string(), v.any()), vCredentialSubjectLeafType])

export const vW3cVcCredentialSubject = v.record(v.string(), vClaimValueSchema)
