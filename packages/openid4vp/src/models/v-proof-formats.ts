import * as v from 'valibot'
export const vProofFormat = v.picklist(['jwt_vp_json', 'ldc_vp', 'ac_vp', 'dc+sd-jwt', 'mso_mdoc'])
export type ProofFormat = v.InferOutput<typeof vProofFormat>
