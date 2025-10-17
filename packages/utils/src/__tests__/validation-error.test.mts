import { describe, expect, test } from 'vitest'
import z from 'zod'
import { ValidationError } from '../error/ValidationError.js'

describe('Validation error', () => {
  test('basic formatting', () => {
    const schema = z.object({
      name: z.string(),
      age: z.number(),
      object: z.object({
        foo: z.object({
          bar: z.discriminatedUnion('type', [
            z.object({ type: z.literal('a'), a: z.string() }),
            z.object({ type: z.literal('b'), b: z.number() }),
          ]),
        }),
      }),
    })

    const result = schema.safeParse({
      object: { foo: { bar: { type: 'z', a: 123 } } },
    })

    const error = new ValidationError('Validation failed', result.error)
    expect(error.message).toMatchInlineSnapshot(`"Validation failed
✖ Invalid input: expected string, received undefined
  → at name
✖ Invalid input: expected number, received undefined
  → at age
✖ Invalid input
  → at object.foo.bar.type"
    `)
  })

  test('should be able to get original zod error instance', () => {
    const schema = z.object({ name: z.string() })
    const result = schema.safeParse({ name: 123 })

    const error = new ValidationError('Validation failed', result.error)
    expect(error.zodError).toBe(result.error)
  })
})
