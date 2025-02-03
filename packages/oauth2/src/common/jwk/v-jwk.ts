import * as v from 'valibot'

export const vJwk = v.looseObject({
  kty: v.string(),
  crv: v.optional(v.string()),
  x: v.optional(v.string()),
  y: v.optional(v.string()),
  e: v.optional(v.string()),
  n: v.optional(v.string()),
  alg: v.optional(v.string()),
  d: v.optional(v.string()),
  dp: v.optional(v.string()),
  dq: v.optional(v.string()),
  ext: v.optional(v.boolean()),
  k: v.optional(v.string()),
  key_ops: v.optional(v.string()),
  kid: v.optional(v.string()),
  oth: v.optional(
    v.array(
      v.looseObject({
        d: v.optional(v.string()),
        r: v.optional(v.string()),
        t: v.optional(v.string()),
      })
    )
  ),
  p: v.optional(v.string()),
  q: v.optional(v.string()),
  qi: v.optional(v.string()),
  use: v.optional(v.string()),
  x5c: v.optional(v.array(v.string())),
  x5t: v.optional(v.string()),
  'x5t#S256': v.optional(v.string()),
  x5u: v.optional(v.string()),
})
export type Jwk = v.InferOutput<typeof vJwk>

export const vJwkSet = v.looseObject({
  keys: v.array(vJwk),
})
export type JwkSet = v.InferOutput<typeof vJwkSet>
