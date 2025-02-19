import { describe, expect, test } from 'vitest'
import { parseCredentialRequest } from '../parse-credential-request'

describe('Parse Credential Request', () => {
  test('parse draft 14 credential request with vc+sd-jwt format', () => {
    expect(
      parseCredentialRequest({
        credentialRequest: {
          format: 'vc+sd-jwt',
          vct: 'some-vct',
          extra_prop: 'should-stay',
          proof: {
            proof_type: 'jwt',
            jwt: 'ey.ey.S',
          },
        },
      })
    ).toStrictEqual({
      proofs: {
        jwt: ['ey.ey.S'],
      },
      format: {
        format: 'vc+sd-jwt',
        vct: 'some-vct',
      },
      credentialRequest: {
        format: 'vc+sd-jwt',
        vct: 'some-vct',
        extra_prop: 'should-stay',
        proof: {
          proof_type: 'jwt',
          jwt: 'ey.ey.S',
        },
      },
    })
  })

  test('parse draft 14 credential request with mso_mdoc format', () => {
    expect(
      parseCredentialRequest({
        credentialRequest: {
          format: 'mso_mdoc',
          doctype: 'eu.pid',
          extra_prop: 'should-stay',
          proof: {
            proof_type: 'jwt',
            jwt: 'ey.ey.S',
          },
        },
      })
    ).toStrictEqual({
      proofs: {
        jwt: ['ey.ey.S'],
      },
      format: {
        format: 'mso_mdoc',
        doctype: 'eu.pid',
      },
      credentialRequest: {
        format: 'mso_mdoc',
        doctype: 'eu.pid',
        extra_prop: 'should-stay',
        proof: {
          proof_type: 'jwt',
          jwt: 'ey.ey.S',
        },
      },
    })
  })

  test('parse draft 14 credential request with ldp_vc format', () => {
    expect(
      parseCredentialRequest({
        credentialRequest: {
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
      })
    ).toStrictEqual({
      format: {
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
      },
      proofs: {
        jwt: ['ey.ey.S'],
      },
      credentialRequest: {
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
    })
  })

  test('parse draft 14 credential request with jwt_vc_json-ld format', () => {
    expect(
      parseCredentialRequest({
        credentialRequest: {
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
      })
    ).toStrictEqual({
      proofs: {
        jwt: ['ey.ey.S'],
      },
      format: {
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
      },
      credentialRequest: {
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
    })
  })

  test('parse draft 14 credential request with jwt_vc_json format', () => {
    expect(
      parseCredentialRequest({
        credentialRequest: {
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
      })
    ).toStrictEqual({
      proofs: {
        jwt: ['ey.ey.S'],
      },
      format: {
        format: 'jwt_vc_json',
        credential_definition: {
          type: ['types'],
          credentialSubject: {
            claim: {
              mandatory: true,
            },
          },
        },
      },
      credentialRequest: {
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
    })
  })

  test('parse draft 14 credential request with known jwt proof_type', () => {
    expect(
      parseCredentialRequest({
        credentialRequest: {
          credential_identifier: 'some-identifier',
          extra_prop: 'should-stay',
          proof: {
            proof_type: 'jwt',
            jwt: 'ey.ey.S',
          },
        },
      })
    ).toStrictEqual({
      proofs: {
        jwt: ['ey.ey.S'],
      },
      credentialIdentifier: 'some-identifier',
      credentialRequest: {
        credential_identifier: 'some-identifier',
        extra_prop: 'should-stay',
        proof: {
          proof_type: 'jwt',
          jwt: 'ey.ey.S',
        },
      },
    })
  })

  test('parse draft 14 credential request with unknown proof_type', () => {
    expect(
      parseCredentialRequest({
        credentialRequest: {
          credential_identifier: 'some-identifier',
          extra_prop: 'should-stay',
          proof: {
            proof_type: 'some-random-proof-type',
            not_a_jwt: 'really',
          },
        },
      })
    ).toStrictEqual({
      proofs: undefined,
      credentialIdentifier: 'some-identifier',
      credentialRequest: {
        credential_identifier: 'some-identifier',
        extra_prop: 'should-stay',
        proof: {
          proof_type: 'some-random-proof-type',
          not_a_jwt: 'really',
        },
      },
    })
  })

  test('parse draft 14 credential request with known proofs jwt array', () => {
    expect(
      parseCredentialRequest({
        credentialRequest: {
          credential_identifier: 'some-identifier',
          extra_prop: 'should-stay',
          proofs: {
            jwt: ['ey.ey.S', 'ey.ey.S'],
          },
        },
      })
    ).toStrictEqual({
      proofs: {
        jwt: ['ey.ey.S', 'ey.ey.S'],
      },
      credentialIdentifier: 'some-identifier',
      credentialRequest: {
        credential_identifier: 'some-identifier',
        extra_prop: 'should-stay',
        proofs: {
          jwt: ['ey.ey.S', 'ey.ey.S'],
        },
      },
    })
  })

  test('parse draft 14 credential request with unknown proofs array', () => {
    expect(
      parseCredentialRequest({
        credentialRequest: {
          credential_identifier: 'some-identifier',
          extra_prop: 'should-stay',
          proofs: {
            not_a_jwt: [{ one: true }, { two: true }],
          },
        },
      })
    ).toStrictEqual({
      proofs: undefined,
      credentialIdentifier: 'some-identifier',
      credentialRequest: {
        credential_identifier: 'some-identifier',
        extra_prop: 'should-stay',
        proofs: {
          not_a_jwt: [{ one: true }, { two: true }],
        },
      },
    })
  })

  test('parse draft 14 credential request without format with credential_identifier', () => {
    expect(
      parseCredentialRequest({
        credentialRequest: {
          credential_identifier: 'some-identifier',
          extra_prop: 'should-stay',
          proof: {
            proof_type: 'jwt',
            jwt: 'ey.ey.S',
          },
        },
      })
    ).toStrictEqual({
      proofs: {
        jwt: ['ey.ey.S'],
      },
      credentialIdentifier: 'some-identifier',
      credentialRequest: {
        credential_identifier: 'some-identifier',
        extra_prop: 'should-stay',
        proof: {
          proof_type: 'jwt',
          jwt: 'ey.ey.S',
        },
      },
    })
  })

  test('parse draft 14 credential request without recognized format', () => {
    expect(
      parseCredentialRequest({
        credentialRequest: {
          format: 'a-new-format',
          some_random_prop: 'should-be-allowed',
          proofs: {
            jwt: ['ey.ey.S'],
          },
        },
      })
    ).toStrictEqual({
      proofs: {
        jwt: ['ey.ey.S'],
      },
      credentialRequest: {
        format: 'a-new-format',
        some_random_prop: 'should-be-allowed',
        proofs: {
          jwt: ['ey.ey.S'],
        },
      },
    })
  })

  test('parse draft 11 credential request with jwt_vc_json format and transfrom to draft 14', () => {
    expect(
      parseCredentialRequest({
        credentialRequest: {
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
        },
      })
    ).toStrictEqual({
      proofs: {
        jwt: ['ey.ey.S'],
      },
      format: {
        format: 'jwt_vc_json',
        credential_definition: {
          type: ['one', 'two'],
          credentialSubject: {
            some: {
              mandatory: true,
            },
          },
        },
      },
      credentialRequest: {
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
    })
  })

  test('parse draft 11 credential request with jwt_vc_json-ld format and transfrom to draft 14', () => {
    expect(
      parseCredentialRequest({
        credentialRequest: {
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
        },
      })
    ).toStrictEqual({
      format: {
        format: 'jwt_vc_json-ld',
        credential_definition: {
          '@context': ['context'],
          type: ['one', 'two'],
          credentialSubject: {
            some: {
              mandatory: true,
            },
          },
        },
      },
      proofs: {
        jwt: ['ey.ey.S'],
      },
      credentialRequest: {
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
    })
  })

  test('parse draft 11 credential request with ldp_vc format and transfrom to draft 14', () => {
    expect(
      parseCredentialRequest({
        credentialRequest: {
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
        },
      })
    ).toStrictEqual({
      proofs: {
        jwt: ['ey.ey.S'],
      },
      format: {
        format: 'ldp_vc',
        credential_definition: {
          '@context': ['context'],
          type: ['one', 'two'],
          credentialSubject: {
            some: {
              mandatory: true,
            },
          },
        },
      },
      credentialRequest: {
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
    })
  })
})
