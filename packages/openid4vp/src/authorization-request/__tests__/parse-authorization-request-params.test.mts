import { describe, expect, test } from 'vitest'
import { parseOpenid4vpAuthorizationRequest } from '../parse-authorization-request-params.js'

describe('Parse Authorization Request Params', () => {
  test('parse authorization request uri and transforms string JSON fields to JSON', () => {
    expect(
      parseOpenid4vpAuthorizationRequest({
        authorizationRequest: `openid4vp://?client_id=test&presentation_definition=${encodeURIComponent(JSON.stringify({ id: 'something' }))}&dcql_query=${encodeURIComponent(JSON.stringify({ id: 'something' }))}&client_metadata=${encodeURIComponent(JSON.stringify({ my: 'metadata' }))}&transaction_data=${encodeURIComponent(JSON.stringify(['something']))}`,
      })
    ).toEqual({
      type: 'openid4vp',
      provided: 'uri',
      params: {
        client_id: 'test',
        presentation_definition: { id: 'something' },
        client_metadata: { my: 'metadata' },
        dcql_query: { id: 'something' },
        transaction_data: ['something'],
      },
    })
  })
})
