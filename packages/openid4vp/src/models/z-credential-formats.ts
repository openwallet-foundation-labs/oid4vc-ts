import { z } from 'zod'
export const zCredentialFormat = z.enum(['jwt_vc_json', 'ldp_vc', 'ac_vc', 'mso_mdoc', 'dc+sd-jwt', 'vc+sd-jwt'])
export type CredentialFormat = z.infer<typeof zCredentialFormat>
