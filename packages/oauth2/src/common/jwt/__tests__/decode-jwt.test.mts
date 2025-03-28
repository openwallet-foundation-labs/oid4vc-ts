import { describe, expect, test } from 'vitest'
import { jwtSignerFromJwt } from '../decode-jwt.js'

describe('Decode JWT', () => {
  describe('jwtSignerFromJwt', () => {
    test('x5c header', () => {
      expect(jwtSignerFromJwt({ header: { x5c: ['cert'], alg: 'ES256' }, payload: {} })).toEqual({
        method: 'x5c',
        x5c: ['cert'],
        alg: 'ES256',
      })
    })

    test('did kid header', () => {
      expect(jwtSignerFromJwt({ header: { kid: 'did:web:example.com#123', alg: 'ES256' }, payload: {} })).toEqual({
        method: 'did',
        didUrl: 'did:web:example.com#123',
        alg: 'ES256',
      })
    })

    test('did kid header with iss', () => {
      expect(
        jwtSignerFromJwt({ header: { kid: '#123', alg: 'ES256' }, payload: { iss: 'did:web:example.com' } })
      ).toEqual({
        method: 'did',
        didUrl: 'did:web:example.com#123',
        alg: 'ES256',
      })
    })

    test('did in kid mismatch with iss', () => {
      expect(() =>
        jwtSignerFromJwt({
          header: { kid: 'did:web:example.nl#123', alg: 'ES256' },
          payload: { iss: 'did:web:example.com' },
        })
      ).toThrow(
        `Unable to extract signer method from jwt. Found 1 allowed signer method(s) but contained invalid configuration:
FAILED: method did - kid in header starst with did that is different from did value in 'iss'`
      )
    })

    test('iss did but kid does not start with #', () => {
      expect(() =>
        jwtSignerFromJwt({
          header: { kid: '123', alg: 'ES256' },
          payload: { iss: 'did:web:example.com' },
        })
      ).toThrow(
        `Unable to extract signer method from jwt. Found 1 allowed signer method(s) but contained invalid configuration:
FAILED: method did - kid in header must start with either 'did:' or '#' when 'iss' value is a did`
      )
    })

    test('jwk header', () => {
      expect(
        jwtSignerFromJwt({
          header: {
            // @ts-ignore
            jwk: { kid: 'kid' },
            alg: 'ES256',
          },
          payload: {},
        })
      ).toEqual({
        method: 'jwk',
        publicJwk: {
          kid: 'kid',
        },
        alg: 'ES256',
      })
    })

    test('custom', () => {
      expect(
        jwtSignerFromJwt({
          header: {
            alg: 'ES256',
          },
          payload: {},
        })
      ).toEqual({
        method: 'custom',
        alg: 'ES256',
      })
    })

    test('allowed methods success', () => {
      expect(
        jwtSignerFromJwt({
          header: {
            alg: 'ES256',
            kid: 'did:example:123#123',
          },
          payload: {},
          allowedSignerMethods: ['did'],
        })
      ).toEqual({
        method: 'did',
        didUrl: 'did:example:123#123',
        alg: 'ES256',
      })
    })

    test('allowed methods error with valid methods', () => {
      expect(() =>
        jwtSignerFromJwt({
          header: {
            alg: 'ES256',
            kid: 'did:example:123#123',
          },
          payload: {},
          allowedSignerMethods: [],
        })
      ).toThrow(`Unable to extract signer method from jwt. Found 1 signer method(s) that are not allowed:
SUCCEEDED: method did`)
    })

    test('allowed methods error with valid and invalid methods', () => {
      expect(() =>
        jwtSignerFromJwt({
          header: {
            alg: 'ES256',
            kid: 'did:example.com#123',
            // @ts-ignore
            jwk: {},
            trust_chain: [''],
            x5c: ['cert'],
          },
          payload: { iss: 'did:examle.nl' },
          allowedSignerMethods: [],
        })
      ).toThrow(`Unable to extract signer method from jwt. Found 4 signer method(s) that are not allowed:
SUCCEEDED: method x5c
SUCCEEDED: method federation
FAILED: method did - kid in header starst with did that is different from did value in 'iss'
SUCCEEDED: method jwk`)
    })

    test('no allowed methods no custom', () => {
      expect(() =>
        jwtSignerFromJwt({
          header: {
            alg: 'ES256',
          },
          payload: {},
          allowedSignerMethods: [],
        })
      ).toThrow(
        `Unable to extract signer method from jwt. Found no signer methods and 'custom' signer method is not allowed.`
      )
    })
  })
})
