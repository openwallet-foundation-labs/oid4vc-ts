import * as v from 'valibot'
import { expect, test } from 'vitest'
import { vAuthorizationServerMetadata } from '../v-authorization-server-metadata'

test('should parse authorization server metadata', () => {
  // Correct
  expect(
    v.safeParse(vAuthorizationServerMetadata, {
      issuer: 'https://authorization.com',
      token_endpoint: 'https://authorization.com/token',
    })
  ).toStrictEqual({
    issues: undefined,
    output: expect.objectContaining({}),
    success: true,
    typed: true,
  })

  // Incorrect
  expect(
    v.safeParse(vAuthorizationServerMetadata, {
      issuer: 'uri:not-valid',
    })
  ).toStrictEqual({
    issues: expect.any(Array),
    output: expect.objectContaining({}),
    success: false,
    typed: false,
  })
})
