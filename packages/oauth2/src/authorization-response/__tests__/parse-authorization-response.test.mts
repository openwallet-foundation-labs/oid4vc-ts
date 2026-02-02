import { describe, expect, test } from 'vitest'
import { parseAuthorizationResponseRedirectUrl } from '../parse-authorization-response'

describe('Parse Authorization Response', () => {
  describe(`parseAuthorizationResponseRedirectUrl`, () => {
    test('parses successful response', () => {
      expect(
        parseAuthorizationResponseRedirectUrl({
          url: 'https://example.com/redirect?code=auth-code-123&state=xyz',
        })
      ).toMatchObject({
        code: 'auth-code-123',
        state: 'xyz',
      })
    })

    test('parses error response', () => {
      expect(
        parseAuthorizationResponseRedirectUrl({
          url: 'https://example.com/redirect?state=xyz&error=access_denied',
        })
      ).toMatchObject({
        state: 'xyz',
        error: 'access_denied',
      })
    })

    test('throws on invalid response', () => {
      expect(() =>
        parseAuthorizationResponseRedirectUrl({
          url: 'https://example.com/redirect?state=xyz',
        })
      ).toThrow('Error occurred during validation of authorization response redirect URL')
    })
  })
})
