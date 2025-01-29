import { expect, test } from 'vitest'
import { vAuthorizationServerMetadata } from '../v-authorization-server-metadata'

test('should parse authorization server metadata', () => {
  // Correct
  const r1 = vAuthorizationServerMetadata.safeParse({
    issuer: 'https://authorization.com',
    token_endpoint: 'https://authorization.com/token',
  })

  expect(r1.success).toBe(true)

  // Incorrect
  const r2 = vAuthorizationServerMetadata.safeParse({
    issuer: 'uri:not-valid',
  })
  expect(r2.success).toBe(false)
  expect(r2.error?.issues).toBeInstanceOf(Array)
})
