import { describe, expect, test } from 'vitest'
import { parsePushedAuthorizationRequestUriReferenceValue } from '../parse-pushed-authorization-request'

describe('Parse Pushed Authorization Response', () => {
  describe(`parsePushedAuthorizationRequestUriReferenceValue`, () => {
    test('parses valid uri', () => {
      expect(
        parsePushedAuthorizationRequestUriReferenceValue({
          uri: 'urn:ietf:params:oauth:request_uri:mamma-mia',
        })
      ).toEqual('mamma-mia')
    })

    test('throws on invalid uri', () => {
      expect(() =>
        parsePushedAuthorizationRequestUriReferenceValue({
          uri: 'foo bar',
        })
      ).toThrow(`The 'request_uri' must start with the prefix "urn:ietf:params:oauth:request_uri:".`)
    })
  })
})
