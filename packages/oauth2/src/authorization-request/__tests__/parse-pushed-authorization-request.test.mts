import { describe, expect, test } from 'vitest'
import { parsePushedAuthorizationRequestUri } from '../parse-pushed-authorization-request.js'

describe('Parse Pushed Authorization Response', () => {
  describe(`parsePushedAuthorizationRequestUri`, () => {
    test('parses valid uri', () => {
      expect(
        parsePushedAuthorizationRequestUri({
          uri: 'urn:ietf:params:oauth:request_uri:mamma-mia',
        })
      ).toEqual('mamma-mia')
    })

    test('throws on invalid uri', () => {
      expect(() =>
        parsePushedAuthorizationRequestUri({
          uri: 'foo bar',
        })
      ).toThrow(`The 'request_uri' must start with the prefix "urn:ietf:params:oauth:request_uri:".`)
    })
  })
})
