import { valibotRecursiveFlattenIssues } from '@animo-id/oauth2-utils'
import * as v from 'valibot'
import { describe, expect, test } from 'vitest'
import { vCredentialRequest, vCredentialRequestDraft11To14 } from '../v-credential-request'

describe('Credential Request', () => {
  test('error when both proof and proofs are defined', () => {
    const parseResult = v.safeParse(vCredentialRequest, {
      format: 'vc+sd-jwt',
      vct: 'some-vct',
      extra_prop: 'should-stay',
      proof: {
        proof_type: 'jwt',
        jwt: 'ey.ey.S',
      },
      proofs: {
        jwt: ['ey.ey.S'],
      },
    })

    expect(parseResult).toStrictEqual({
      issues: [
        expect.objectContaining({
          message: "Both 'proof' and 'proofs' are defined. Only one is allowed",
        }),
      ],
      output: expect.any(Object),
      success: false,
      typed: true,
    })
  })

  test('error when both format and credential_identifier are defined', () => {
    const parseResult = v.safeParse(vCredentialRequest, {
      format: 'vc+sd-jwt',
      vct: 'some-vct',
      credential_identifier: 'some',
      extra_prop: 'should-stay',
      proof: {
        proof_type: 'jwt',
        jwt: 'ey.ey.S',
      },
    })

    expect(valibotRecursiveFlattenIssues(parseResult.issues ?? [])).toMatchObject({
      nested: {
        credential_identifier: ["'credential_identifier' cannot be defined when 'format' is set."],
      },
    })

    expect(parseResult).toStrictEqual({
      issues: expect.any(Array),
      output: expect.any(Object),
      success: false,
      typed: false,
    })
  })

  test('parse draft 14 credential request with vc+sd-jwt format', () => {
    const parseResult = v.safeParse(vCredentialRequest, {
      format: 'vc+sd-jwt',
      vct: 'some-vct',
      extra_prop: 'should-stay',
      proof: {
        proof_type: 'jwt',
        jwt: 'ey.ey.S',
      },
    })

    expect(parseResult).toStrictEqual({
      issues: undefined,
      output: {
        format: 'vc+sd-jwt',
        vct: 'some-vct',
        extra_prop: 'should-stay',
        proof: {
          proof_type: 'jwt',
          jwt: 'ey.ey.S',
        },
      },
      success: true,
      typed: true,
    })
  })

  test('parse draft 14 credential request with mso_mdoc format', () => {
    const parseResult = v.safeParse(vCredentialRequest, {
      format: 'mso_mdoc',
      doctype: 'eu.pid',
      extra_prop: 'should-stay',
      proof: {
        proof_type: 'jwt',
        jwt: 'ey.ey.S',
      },
    })

    expect(parseResult).toStrictEqual({
      issues: undefined,
      output: {
        format: 'mso_mdoc',
        doctype: 'eu.pid',
        extra_prop: 'should-stay',
        proof: {
          proof_type: 'jwt',
          jwt: 'ey.ey.S',
        },
      },
      success: true,
      typed: true,
    })
  })

  test('parse draft 14 credential request with ldp_vc format', () => {
    const parseResult = v.safeParse(vCredentialRequest, {
      format: 'ldp_vc',
      credential_definition: {
        '@context': ['context'],
        type: ['types'],
        credentialSubject: {
          claim: {
            mandatory: true,
          },
        },
      },
      extra_prop: 'should-stay',
      proof: {
        proof_type: 'jwt',
        jwt: 'ey.ey.S',
      },
    })

    expect(parseResult).toStrictEqual({
      issues: undefined,
      output: {
        format: 'ldp_vc',
        credential_definition: {
          '@context': ['context'],
          type: ['types'],
          credentialSubject: {
            claim: {
              mandatory: true,
            },
          },
        },
        extra_prop: 'should-stay',
        proof: {
          proof_type: 'jwt',
          jwt: 'ey.ey.S',
        },
      },
      success: true,
      typed: true,
    })
  })

  test('parse draft 14 credential request with jwt_vc_json-ld format', () => {
    const parseResult = v.safeParse(vCredentialRequest, {
      format: 'jwt_vc_json-ld',
      credential_definition: {
        '@context': ['context'],
        type: ['types'],
        credentialSubject: {
          claim: {
            mandatory: true,
          },
        },
      },
      extra_prop: 'should-stay',
      proof: {
        proof_type: 'jwt',
        jwt: 'ey.ey.S',
      },
    })

    expect(parseResult).toStrictEqual({
      issues: undefined,
      output: {
        format: 'jwt_vc_json-ld',
        credential_definition: {
          '@context': ['context'],
          type: ['types'],
          credentialSubject: {
            claim: {
              mandatory: true,
            },
          },
        },
        extra_prop: 'should-stay',
        proof: {
          proof_type: 'jwt',
          jwt: 'ey.ey.S',
        },
      },
      success: true,
      typed: true,
    })
  })

  test('parse draft 14 credential request with jwt_vc_json format', () => {
    const parseResult = v.safeParse(vCredentialRequest, {
      format: 'jwt_vc_json',
      credential_definition: {
        type: ['types'],
        credentialSubject: {
          claim: {
            mandatory: true,
          },
        },
      },
      extra_prop: 'should-stay',
      proof: {
        proof_type: 'jwt',
        jwt: 'ey.ey.S',
      },
    })

    expect(parseResult).toStrictEqual({
      issues: undefined,
      output: {
        format: 'jwt_vc_json',
        credential_definition: {
          type: ['types'],
          credentialSubject: {
            claim: {
              mandatory: true,
            },
          },
        },
        extra_prop: 'should-stay',
        proof: {
          proof_type: 'jwt',
          jwt: 'ey.ey.S',
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
        jwt: 'ey.ey.S',
      },
    })

    expect(parseResult).toStrictEqual({
      issues: undefined,
      output: {
        credential_identifier: 'some-identifier',
        proof: {
          proof_type: 'jwt',
          jwt: 'ey.ey.S',
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
        jwt: 'ey.ey.S',
      },
    })

    expect(parseResult).toStrictEqual({
      issues: undefined,
      output: {
        format: 'a-new-format',
        some_random_prop: 'should-be-allowed',
        proof: {
          proof_type: 'jwt',
          jwt: 'ey.ey.S',
        },
      },
      success: true,
      typed: true,
    })
  })

  test('parse draft 11 credential request with jwt_vc_json format and transfrom to draft 14', () => {
    const parseResult = v.safeParse(vCredentialRequestDraft11To14, {
      format: 'jwt_vc_json',
      types: ['one', 'two'],
      some_other_prop: 'should-stay',
      credentialSubject: {
        some: {
          mandatory: true,
        },
      },
      proof: {
        proof_type: 'jwt',
        jwt: 'ey.ey.S',
      },
    })

    expect(parseResult).toStrictEqual({
      issues: undefined,
      output: {
        format: 'jwt_vc_json',
        some_other_prop: 'should-stay',
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
          jwt: 'ey.ey.S',
        },
      },
      success: true,
      typed: true,
    })
  })

  test('parse draft 11 credential request with jwt_vc_json-ld format and transfrom to draft 14', () => {
    const parseResult = v.safeParse(vCredentialRequest, {
      format: 'jwt_vc_json-ld',
      credential_definition: {
        '@context': ['context'],
        types: ['one', 'two'],
        credentialSubject: {
          some: {
            mandatory: true,
          },
        },
      },
      some_other_prop: 'should-stay',
      proof: {
        proof_type: 'jwt',
        jwt: 'ey.ey.S',
      },
    })

    expect(parseResult).toStrictEqual({
      issues: undefined,
      output: {
        format: 'jwt_vc_json-ld',
        some_other_prop: 'should-stay',
        credential_definition: {
          '@context': ['context'],
          type: ['one', 'two'],
          credentialSubject: {
            some: {
              mandatory: true,
            },
          },
        },
        proof: {
          proof_type: 'jwt',
          jwt: 'ey.ey.S',
        },
      },
      success: true,
      typed: true,
    })
  })

  test('parse draft 11 credential request with ldp_vc format and transfrom to draft 14', () => {
    const parseResult = v.safeParse(vCredentialRequest, {
      format: 'ldp_vc',
      credential_definition: {
        '@context': ['context'],
        types: ['one', 'two'],
        credentialSubject: {
          some: {
            mandatory: true,
          },
        },
      },
      some_other_prop: 'should-stay',
      proof: {
        proof_type: 'jwt',
        jwt: 'ey.ey.S',
      },
    })

    expect(parseResult).toStrictEqual({
      issues: undefined,
      output: {
        format: 'ldp_vc',
        some_other_prop: 'should-stay',
        credential_definition: {
          '@context': ['context'],
          type: ['one', 'two'],
          credentialSubject: {
            some: {
              mandatory: true,
            },
          },
        },
        proof: {
          proof_type: 'jwt',
          jwt: 'ey.ey.S',
        },
      },
      success: true,
      typed: true,
    })
  })
})
