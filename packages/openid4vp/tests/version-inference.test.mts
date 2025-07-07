import { describe, expect, test } from 'vitest'
import { parseAuthorizationRequestVersion } from '../src/version.js'

describe('Version inference test', () => {
  test('w3c_dc_api is only available in v22 and below', () => {
    const version = parseAuthorizationRequestVersion({
      response_mode: 'w3c_dc_api',
      nonce: 'nonce',
      response_type: 'vp_token',
    })

    expect(version).toBe(22)
  })

  test('dc_api is only available from v23', () => {
    const version = parseAuthorizationRequestVersion({
      response_mode: 'dc_api',
      nonce: 'nonce',
      response_type: 'vp_token',
    })

    expect(version).toBe(29)
  })

  test('client_metadata_uri requires version below 21', () => {
    const version = parseAuthorizationRequestVersion({
      response_mode: 'direct_post',
      client_id: 'client_id',
      nonce: 'nonce',
      response_type: 'vp_token',
      client_metadata_uri: 'https://example.com',
    })

    expect(version).toBe(20)
  })
})
