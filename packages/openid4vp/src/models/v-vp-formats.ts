import * as v from 'valibot'

export const vVpFormats = v.optional(v.record(v.string(), v.unknown()))
export type VpFormats = v.InferOutput<typeof vVpFormats>
