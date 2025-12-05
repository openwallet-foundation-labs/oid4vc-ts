import { describe, expect, test } from 'vitest'
import { zCredentialRequest, zCredentialRequestDraft11To14 } from '../z-credential-request.js'

describe('Credential Request', () => {
  test('error when both proof and proofs are defined', () => {
    const parseResult = zCredentialRequest.safeParse({
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

    expect(parseResult.success).toBe(false)
    expect(JSON.stringify(parseResult.error)).includes("Both 'proof' and 'proofs' are defined. Only one is allowed")
  })

  test('valid when both format and credential_identifier are defined', () => {
    const parseResult = zCredentialRequest.safeParse({
      format: 'vc+sd-jwt',
      vct: 'some-vct',
      credential_identifier: 'some',
      extra_prop: 'should-stay',
      proof: {
        proof_type: 'jwt',
        jwt: 'ey.ey.S',
      },
    })

    expect(parseResult.success).toBe(true)
  })

  test('parse draft 14 credential request with vc+sd-jwt format', () => {
    const parseResult = zCredentialRequest.safeParse({
      format: 'vc+sd-jwt',
      vct: 'some-vct',
      extra_prop: 'should-stay',
      proof: {
        proof_type: 'jwt',
        jwt: 'ey.ey.S',
      },
    })

    expect(parseResult).toStrictEqual({
      data: {
        format: 'vc+sd-jwt',
        vct: 'some-vct',
        extra_prop: 'should-stay',
        proof: {
          proof_type: 'jwt',
          jwt: 'ey.ey.S',
        },
      },
      success: true,
    })
  })

  test('parse draft 14 credential request with mso_mdoc format', () => {
    const parseResult = zCredentialRequest.safeParse({
      format: 'mso_mdoc',
      doctype: 'eu.pid',
      extra_prop: 'should-stay',
      proof: {
        proof_type: 'jwt',
        jwt: 'ey.ey.S',
      },
    })

    expect(parseResult).toStrictEqual({
      data: {
        format: 'mso_mdoc',
        doctype: 'eu.pid',
        extra_prop: 'should-stay',
        proof: {
          proof_type: 'jwt',
          jwt: 'ey.ey.S',
        },
      },
      success: true,
    })
  })

  test('parse draft 14 credential request with ldp_vc format', () => {
    const parseResult = zCredentialRequest.safeParse({
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
      data: {
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
    })
  })

  test('parse draft 14 credential request with jwt_vc_json-ld format', () => {
    const parseResult = zCredentialRequest.safeParse({
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
      data: {
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
    })
  })

  test('parse draft 14 credential request with jwt_vc_json format', () => {
    const parseResult = zCredentialRequest.safeParse({
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
      data: {
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
    })
  })

  test('parse draft 14 credential request without format with credential_identifier', () => {
    const parseResult = zCredentialRequest.safeParse({
      credential_identifier: 'some-identifier',
      proof: {
        proof_type: 'jwt',
        jwt: 'ey.ey.S',
      },
    })

    expect(parseResult).toStrictEqual({
      data: {
        credential_identifier: 'some-identifier',
        proof: {
          proof_type: 'jwt',
          jwt: 'ey.ey.S',
        },
      },
      success: true,
    })
  })

  test('parse draft 14 credential request without recognized format', () => {
    const parseResult = zCredentialRequest.safeParse({
      format: 'a-new-format',
      some_random_prop: 'should-be-allowed',
      proof: {
        proof_type: 'jwt',
        jwt: 'ey.ey.S',
      },
    })

    expect(parseResult).toStrictEqual({
      data: {
        format: 'a-new-format',
        some_random_prop: 'should-be-allowed',
        proof: {
          proof_type: 'jwt',
          jwt: 'ey.ey.S',
        },
      },
      success: true,
    })
  })

  test('parse draft 11 credential request with jwt_vc_json format and transfrom to draft 14', () => {
    const parseResult = zCredentialRequestDraft11To14.safeParse({
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
      data: {
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
    })
  })

  test('parse draft 11 credential request with jwt_vc_json-ld format and transfrom to draft 14', () => {
    const parseResult = zCredentialRequest.safeParse({
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
      data: {
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
    })
  })

  test('parse draft 11 credential request with ldp_vc format and transfrom to draft 14', () => {
    const parseResult = zCredentialRequest.safeParse({
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
      data: {
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
    })
  })
})
