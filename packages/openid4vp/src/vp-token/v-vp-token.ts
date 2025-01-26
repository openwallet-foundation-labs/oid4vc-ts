import * as v from 'valibot'
export const vVpToken = v.union([v.string(), v.array(v.string()), v.record(v.string(), v.unknown())])
export type VpToken = v.InferOutput<typeof vVpToken>
