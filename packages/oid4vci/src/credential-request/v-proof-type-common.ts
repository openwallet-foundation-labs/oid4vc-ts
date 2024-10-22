import * as v from 'valibot'

export const vCredentialRequestProofCommon = v.looseObject({
  proof_type: v.string(),
})
