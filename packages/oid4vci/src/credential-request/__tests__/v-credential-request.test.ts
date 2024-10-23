import * as v from 'valibot'
import { describe, expect, test } from 'vitest'
import { vCredentialRequest } from '../v-credential-request'

describe('Credential Request', () => {
  test('parse draft 14 credential request with recognized format', () => {
    const parseResult = v.safeParse(vCredentialRequest, {
      format: 'vc+sd-jwt',
      vct: 'some-vct',
      proof: {
        proof_type: 'jwt',
        jwt: 'hello',
      },
    })

    expect(parseResult).toStrictEqual({
      issues: undefined,
      output: {
        format: 'vc+sd-jwt',
        vct: 'some-vct',
        proof: {
          proof_type: 'jwt',
          jwt: 'hello',
        },
      },
      success: true,
      typed: true,
    })
  })

  test('parse draft 14 credential request without format with credential_identifier', () => {
    const parseResult = v.safeParse(vCredentialRequest, {
      credential_identifier: 'some-identifier',
      proof: {
        proof_type: 'jwt',
        jwt: 'hello',
      },
    })

    expect(parseResult).toStrictEqual({
      issues: undefined,
      output: {
        credential_identifier: 'some-identifier',
        proof: {
          proof_type: 'jwt',
          jwt: 'hello',
        },
      },
      success: true,
      typed: true,
    })
  })

  test('parse draft 14 credential request without recognized format', () => {
    const parseResult = v.safeParse(vCredentialRequest, {
      format: 'a-new-format',
      some_random_prop: 'should-be-allowed',
      proof: {
        proof_type: 'jwt',
        jwt: 'hello',
      },
    })

    expect(parseResult).toStrictEqual({
      issues: undefined,
      output: {
        format: 'a-new-format',
        some_random_prop: 'should-be-allowed',
        proof: {
          proof_type: 'jwt',
          jwt: 'hello',
        },
      },
      success: true,
      typed: true,
    })
  })

  test('parse draft 11 credential request with recognized format and transfrom to draft 14', () => {
    const parseResult = v.safeParse(vCredentialRequest, {
      format: 'jwt_vc_json',
      types: ['one', 'two'],
      credentialSubject: {
        some: {
          mandatory: true,
        },
      },
      proof: {
        proof_type: 'jwt',
        jwt: 'hello',
      },
    })

    expect(parseResult).toStrictEqual({
      issues: undefined,
      output: {
        format: 'jwt_vc_json',
        credential_definition: {
          type: ['one', 'two'],
          credentialSubject: {
            some: {
              mandatory: true,
            },
          },
        },
        proof: {
          proof_type: 'jwt',
          jwt: 'hello',
        },
      },
      success: true,
      typed: true,
    })
  })
})
