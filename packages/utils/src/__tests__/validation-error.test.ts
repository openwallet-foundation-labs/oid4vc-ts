import { describe, expect, test } from 'vitest'
import z from 'zod'
import { ValidationError } from '../error/ValidationError'

describe('Validation error', () => {
  test('basic', () => {
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
    expect(error.message).toMatchInlineSnapshot(`
      "[ValidationError] Validation failed
      	- Required at "name"
      	- Required at "age"
      	- Invalid discriminator value. Expected 'a' | 'b' at "object.foo.bar.type""
    `)
  })
})
