import { describe, expect, test } from 'vitest'
import { decodeJwt, jwtSignerFromJwt } from '../decode-jwt.js'
import { zJwtHeader, zJwtPayload } from '../z-jwt.js'

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
FAILED: method did - kid in header starts with did that is different from did value in 'iss'`
      )
    })

    test('did in kid mismatch with iss but allowed since header typ is openid4vci-proof+jwt', () => {
      expect(
        jwtSignerFromJwt({
          header: { kid: 'did:web:example.nl#123', alg: 'ES256', typ: 'openid4vci-proof+jwt' },
          payload: { iss: 'some_client_id' },
        })
      ).toEqual({
        method: 'did',
        didUrl: 'did:web:example.nl#123',
        alg: 'ES256',
      })
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
            // @ts-expect-error
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
            // @ts-expect-error
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
FAILED: method did - kid in header starts with did that is different from did value in 'iss'
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

  describe('decodeJwt', () => {
    test('array aud', () => {
      const jwt = decodeJwt({
        jwt: 'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImZvbyIsImJhciJdLCJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZSwiaWF0IjoxNTE2MjM5MDIyfQ.ji0QSA0yyzq4NTh4kkbR0hrcJz0blM_6V2jyD5hHWTL6XR9kbQ6lCfV8qcpQncpA4dv-NRVZjvw4t7Jlf_EqDQ',
        headerSchema: zJwtHeader,
        payloadSchema: zJwtPayload,
      })

      expect(jwt).toMatchObject({
        header: {
          alg: 'EdDSA',
          typ: 'JWT',
        },
        payload: {
          sub: '1234567890',
          aud: ['foo', 'bar'],
          name: 'John Doe',
          admin: true,
          iat: 1516239022,
        },
      })
    })

    test('non-integer timestamps (RFC 7519 NumericDate compliance)', () => {
      // JWT with non-integer iat, exp, and nbf values
      // Payload: {"iss":"did:example:123","aud":"https://example.com","iat":1769780135.5225298,"exp":1769783735.5225298,"nbf":1769780135.5225298}
      const jwt = decodeJwt({
        jwt: 'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZToxMjMiLCJhdWQiOiJodHRwczovL2V4YW1wbGUuY29tIiwiaWF0IjoxNzY5NzgwMTM1LjUyMjUyOTgsImV4cCI6MTc2OTc4MzczNS41MjI1Mjk4LCJuYmYiOjE3Njk3ODAxMzUuNTIyNTI5OH0.BXhRLNzuJn8xOCgPl9jTrX8xdqVxCy4PCB9vHbz8KZYwAhE2x-vXNq8x_4yFXG7jt__fIyT_vFPxHzQPcGFXBA',
        headerSchema: zJwtHeader,
        payloadSchema: zJwtPayload,
      })

      expect(jwt).toMatchObject({
        header: {
          alg: 'EdDSA',
          typ: 'JWT',
        },
        payload: {
          iss: 'did:example:123',
          aud: 'https://example.com',
          iat: 1769780135.5225298,
          exp: 1769783735.5225298,
          nbf: 1769780135.5225298,
        },
      })
    })
  })
})
