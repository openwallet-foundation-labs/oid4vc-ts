import { describe, expect, test } from 'vitest'
import { encodeWwwAuthenticateHeader, parseWwwAuthenticateHeader } from '../www-authenticate'

describe('WWW-Authenticate Header', () => {
  test('Correctly parses single scheme', () => {
    expect(
      parseWwwAuthenticateHeader('Custom foo=bar,foo=fuzz,buzz="quoted \\"value!\\"", Bearer="true", name, age')
    ).toEqual([
      {
        payload: {
          Bearer: 'true',
          buzz: 'quoted "value!"',
          foo: ['bar', 'fuzz'],
          name: null,
          age: null,
        },
        scheme: 'Custom',
      },
    ])
  })

  test('Correctly parses multiple schemes with well-known scheme names', () => {
    expect(
      parseWwwAuthenticateHeader(
        'Custom foo=bar,foo=fuzz,buzz="quoted \\"value!\\"", Bearer="true", name, age, Bearer, Basic name="Timo", DPoP name="Timo", DPoP name="again", Bearer'
      )
    ).toEqual([
      {
        payload: {
          Bearer: 'true',
          buzz: 'quoted "value!"',
          foo: ['bar', 'fuzz'],
          name: null,
          age: null,
        },
        scheme: 'Custom',
      },
      {
        payload: {},
        scheme: 'Bearer',
      },
      {
        payload: {
          name: 'Timo',
        },
        scheme: 'Basic',
      },
      {
        payload: {
          name: 'Timo',
        },
        scheme: 'DPoP',
      },
      {
        payload: {
          name: 'again',
        },
        scheme: 'DPoP',
      },
      {
        payload: {},
        scheme: 'Bearer',
      },
    ])
  })

  test('Correctly encodes multiple schemes', () => {
    expect(
      encodeWwwAuthenticateHeader([
        {
          payload: {
            Bearer: 'true',
            buzz: 'quoted "value!"',
            foo: ['bar', 'fuzz'],
            name: null,
            age: null,
          },
          scheme: 'Custom',
        },
        {
          payload: {},
          scheme: 'Bearer',
        },
        {
          payload: {
            name: 'Timo',
          },
          scheme: 'Basic',
        },
        {
          payload: {
            name: 'Timo',
          },
          scheme: 'DPoP',
        },
        {
          payload: {
            name: 'again',
          },
          scheme: 'DPoP',
        },
        {
          payload: {},
          scheme: 'Bearer',
        },
      ])
    ).toEqual(
      'Custom Bearer="true", buzz="quoted \\"value!\\"", foo="bar", foo="fuzz", name, age, Bearer, Basic name="Timo", DPoP name="Timo", DPoP name="again", Bearer'
    )
  })
})
