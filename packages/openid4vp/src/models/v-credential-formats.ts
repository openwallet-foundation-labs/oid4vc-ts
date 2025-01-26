import * as v from 'valibot'
export const vCredentialFormat = v.picklist(['jwt_vc_json', 'ldp_vc', 'ac_vc', 'mso_mdoc', 'dc+sd-jwt'])
export type CredentialFormat = v.InferOutput<typeof vCredentialFormat>
