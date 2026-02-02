import { describe, expect, test } from 'vitest'
import type { CredentialIssuerMetadata } from '../../metadata/credential-issuer/z-credential-issuer-metadata'
import { Openid4vciVersion } from '../../version'
import { parseCredentialRequest } from '../parse-credential-request'

const issuerMetadata = {
  credential_issuer: 'https://issuer.com',
  credential_configurations_supported: {
    my_credential: {
      format: 'dc+sd-jwt',
      vct: 'hello',
    },
  },
  credential_endpoint: 'https://issuer.com/credential',
} satisfies CredentialIssuerMetadata

describe('Parse Credential Request', () => {
  test('parse draft 15 credential request with credential_configuration_id not in issuer metadata throws error', () => {
    expect(() =>
      parseCredentialRequest({
        issuerMetadata: {
          authorizationServers: [],
          credentialIssuer: issuerMetadata,
          originalDraftVersion: Openid4vciVersion.Draft15,
          knownCredentialConfigurations: {
            my_credential: {
              format: 'dc+sd-jwt',
              vct: 'hello',
            },
          },
        },
        credentialRequest: {
          credential_configuration_id: 'some_random_credential',
          extra_prop: 'should-stay',
          proof: {
            proof_type: 'jwt',
            jwt: 'ey.ey.S',
          },
        },
      })
    ).toThrow(
      "Credential configuration with id 'some_random_credential' not found in credential configurations supported."
    )
  })

  test('parse draft 15 credential request with credential_configuration_id', () => {
    expect(
      parseCredentialRequest({
        issuerMetadata: {
          authorizationServers: [],
          credentialIssuer: issuerMetadata,
          originalDraftVersion: Openid4vciVersion.Draft15,
          knownCredentialConfigurations: {
            my_credential: {
              format: 'dc+sd-jwt',
              vct: 'hello',
            },
          },
        },
        credentialRequest: {
          credential_configuration_id: 'my_credential',
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

      credentialConfigurationId: 'my_credential',
      credentialConfiguration: {
        format: 'dc+sd-jwt',
        vct: 'hello',
      },
      credentialRequest: {
        credential_configuration_id: 'my_credential',
        extra_prop: 'should-stay',
        proof: {
          proof_type: 'jwt',
          jwt: 'ey.ey.S',
        },
      },
    })
  })

  test('parse draft 14 credential request with vc+sd-jwt format', () => {
    expect(
      parseCredentialRequest({
        issuerMetadata: {
          authorizationServers: [],
          credentialIssuer: issuerMetadata,
          originalDraftVersion: Openid4vciVersion.Draft14,
          knownCredentialConfigurations: {
            my_credential: {
              format: 'dc+sd-jwt',
              vct: 'hello',
            },
          },
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
        issuerMetadata: {
          authorizationServers: [],
          credentialIssuer: issuerMetadata,
          originalDraftVersion: Openid4vciVersion.Draft14,
          knownCredentialConfigurations: {
            my_credential: {
              format: 'dc+sd-jwt',
              vct: 'hello',
            },
          },
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
        issuerMetadata: {
          authorizationServers: [],
          credentialIssuer: issuerMetadata,
          originalDraftVersion: Openid4vciVersion.Draft14,
          knownCredentialConfigurations: {
            my_credential: {
              format: 'dc+sd-jwt',
              vct: 'hello',
            },
          },
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
        issuerMetadata: {
          authorizationServers: [],
          credentialIssuer: issuerMetadata,
          originalDraftVersion: Openid4vciVersion.Draft14,
          knownCredentialConfigurations: {
            my_credential: {
              format: 'dc+sd-jwt',
              vct: 'hello',
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
        issuerMetadata: {
          authorizationServers: [],
          credentialIssuer: issuerMetadata,
          originalDraftVersion: Openid4vciVersion.Draft14,
          knownCredentialConfigurations: {
            my_credential: {
              format: 'dc+sd-jwt',
              vct: 'hello',
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
        issuerMetadata: {
          authorizationServers: [],
          credentialIssuer: issuerMetadata,
          originalDraftVersion: Openid4vciVersion.Draft14,
          knownCredentialConfigurations: {
            my_credential: {
              format: 'dc+sd-jwt',
              vct: 'hello',
            },
          },
        },
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
        issuerMetadata: {
          authorizationServers: [],
          credentialIssuer: issuerMetadata,
          originalDraftVersion: Openid4vciVersion.Draft14,
          knownCredentialConfigurations: {
            my_credential: {
              format: 'dc+sd-jwt',
              vct: 'hello',
            },
          },
        },
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
        issuerMetadata: {
          authorizationServers: [],
          credentialIssuer: issuerMetadata,
          originalDraftVersion: Openid4vciVersion.Draft14,
          knownCredentialConfigurations: {
            my_credential: {
              format: 'dc+sd-jwt',
              vct: 'hello',
            },
          },
        },
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
        issuerMetadata: {
          authorizationServers: [],
          credentialIssuer: issuerMetadata,
          originalDraftVersion: Openid4vciVersion.Draft14,
          knownCredentialConfigurations: {
            my_credential: {
              format: 'dc+sd-jwt',
              vct: 'hello',
            },
          },
        },
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
        issuerMetadata: {
          authorizationServers: [],
          credentialIssuer: issuerMetadata,
          originalDraftVersion: Openid4vciVersion.Draft14,
          knownCredentialConfigurations: {
            my_credential: {
              format: 'dc+sd-jwt',
              vct: 'hello',
            },
          },
        },
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
        issuerMetadata: {
          authorizationServers: [],
          credentialIssuer: issuerMetadata,
          originalDraftVersion: Openid4vciVersion.Draft14,
          knownCredentialConfigurations: {
            my_credential: {
              format: 'dc+sd-jwt',
              vct: 'hello',
            },
          },
        },
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
        issuerMetadata: {
          authorizationServers: [],
          credentialIssuer: issuerMetadata,
          originalDraftVersion: Openid4vciVersion.Draft14,
          knownCredentialConfigurations: {
            my_credential: {
              format: 'dc+sd-jwt',
              vct: 'hello',
            },
          },
        },
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
        issuerMetadata: {
          authorizationServers: [],
          credentialIssuer: issuerMetadata,
          originalDraftVersion: Openid4vciVersion.Draft14,
          knownCredentialConfigurations: {
            my_credential: {
              format: 'dc+sd-jwt',
              vct: 'hello',
            },
          },
        },
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
        issuerMetadata: {
          authorizationServers: [],
          credentialIssuer: issuerMetadata,
          originalDraftVersion: Openid4vciVersion.Draft11,
          knownCredentialConfigurations: {
            my_credential: {
              format: 'dc+sd-jwt',
              vct: 'hello',
            },
          },
        },
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
