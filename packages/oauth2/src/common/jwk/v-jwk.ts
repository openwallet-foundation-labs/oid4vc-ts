import z from 'zod'

export const vJwk = z
  .object({
    kty: z.string(),
    crv: z.optional(z.string()),
    x: z.optional(z.string()),
    y: z.optional(z.string()),
    e: z.optional(z.string()),
    n: z.optional(z.string()),
    alg: z.optional(z.string()),
    d: z.optional(z.string()),
    dp: z.optional(z.string()),
    dq: z.optional(z.string()),
    ext: z.optional(z.boolean()),
    k: z.optional(z.string()),
    key_ops: z.optional(z.string()),
    kid: z.optional(z.string()),
    oth: z.optional(
      z.array(
        z
          .object({
            d: z.optional(z.string()),
            r: z.optional(z.string()),
            t: z.optional(z.string()),
          })
          .passthrough()
      )
    ),
    p: z.optional(z.string()),
    q: z.optional(z.string()),
    qi: z.optional(z.string()),
    use: z.optional(z.string()),
    x5c: z.optional(z.string()),
    x5t: z.optional(z.string()),
    'x5t#S256': z.optional(z.string()),
    x5u: z.optional(z.string()),
  })
  .passthrough()

export type Jwk = z.infer<typeof vJwk>

export const vJwkSet = z.object({ keys: z.array(vJwk) }).passthrough()

export type JwkSet = z.infer<typeof vJwkSet>
