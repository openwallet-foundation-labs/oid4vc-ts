import { z } from 'zod'
export const zProofFormat = z.enum(['jwt_vp_json', 'ldc_vp', 'ac_vp', 'dc+sd-jwt', 'vc+sd-jwt', 'mso_mdoc'])
export type ProofFormat = z.infer<typeof zProofFormat>
