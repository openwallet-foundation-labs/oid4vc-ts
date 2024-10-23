import * as v from 'valibot'
import { describe, expect, test } from 'vitest'
import { paradymDraft13 } from '../../../__tests__/__fixtures__/paradym'
import {
  vCredentialConfigurationSupportedWithFormats,
  vCredentialIssuerMetadata,
  vCredentialIssuerMetadataDraft11To14,
} from '../v-credential-issuer-metadata'

describe('Credential Issuer Metadata', () => {
  test('should parse credential configurations supported with format', () => {
    // Correct: sd-jwt with vct
    expect(
      v.safeParse(vCredentialConfigurationSupportedWithFormats, {
        format: 'vc+sd-jwt',
        // vct should be required if format is vc+sd-jwt
        vct: 'SD_JWT_VC_example_in_OpenID4VCI',
      })
    ).toStrictEqual({
      issues: undefined,
      output: expect.objectContaining({}),
      success: true,
      typed: true,
    })

    // Incorrect: sd-jwt without vct
    expect(
      v.safeParse(vCredentialConfigurationSupportedWithFormats, {
        format: 'vc+sd-jwt',
        // vct should be required if format is vc+sd-jwt
        // vct: 'SD_JWT_VC_example_in_OpenID4VCI',
      })
    ).toStrictEqual({
      issues: expect.any(Array),
      output: expect.objectContaining({}),
      success: false,
      typed: false,
    })

    // Correct: mso mdoc with doctype
    expect(
      v.safeParse(vCredentialConfigurationSupportedWithFormats, {
        format: 'mso_mdoc',
        // doctype should be required if format is mso_mdoc
        doctype: 'org.iso.18013.5.1.mDL',
      })
    ).toStrictEqual({
      issues: undefined,
      output: expect.objectContaining({}),
      success: true,
      typed: true,
    })

    // Incorrect: mso mdoc without doctype
    expect(
      v.safeParse(vCredentialConfigurationSupportedWithFormats, {
        format: 'mso_mdoc',
        // doctype should be required if format is mso_mdoc
        // doctype: 'org.iso.18013.5.1.mDL',
      })
    ).toStrictEqual({
      issues: expect.any(Array),
      output: expect.objectContaining({}),
      success: false,
      typed: false,
    })
  })

  test('parse draft 13 credential issuer metadata', () => {
    const parseResult = v.safeParse(vCredentialIssuerMetadata, paradymDraft13.credentialIssuerMetadata)
    expect(parseResult).toStrictEqual({
      issues: undefined,
      output: paradymDraft13.credentialIssuerMetadata,
      success: true,
      typed: true,
    })
  })

  test('parse draft 11 credential issuer metadata', () => {
    const credentials_supported = [
      {
        format: 'vc+sd-jwt',
        vct: 'vct-test-no-id-should-be-removed',
      },
      {
        id: 'sd-jwt',
        format: 'vc+sd-jwt',
        vct: 'vct-test-id',
        display: [
          {
            name: 'hello',
            logo: {
              // should become ur
              url: 'https://logo.com',
            },
            // Should be removed (as now uri is required)
            background_image: {},
          },
        ],
      },
      {
        id: 'w3c-jwt-vc-json',
        format: 'jwt_vc_json',
        types: ['one'],
        extra_property: 'should_stay',
        credentialSubject: {
          name: {
            mandatory: true,
          },
        },
      },
      {
        id: 'w3c-jwt-vc-json-ld',
        format: 'jwt_vc_json-ld',
        types: ['one'],
        '@context': ['two'],
        credentialSubject: {
          name: {
            mandatory: true,
          },
        },
      },
      {
        id: 'w3c-ldp-vc',
        format: 'ldp_vc',
        types: ['one'],
        '@context': ['two'],
        credentialSubject: {
          name: {
            mandatory: true,
          },
        },
        cryptographic_suites_supported: ['EdDSA', 'ES256'],
      },
      {
        id: 'mso-mdoc',
        format: 'mso_mdoc',
        doctype: 'some.doc.type',
        cryptographic_suites_supported: ['EdDSA', 'ES256'],
      },
    ]

    const credential_configurations_supported = {
      'sd-jwt': {
        format: 'vc+sd-jwt',
        vct: 'vct-test-id',
        display: [
          {
            name: 'hello',
            logo: {
              uri: 'https://logo.com',
            },
          },
        ],
      },
      'w3c-jwt-vc-json': {
        format: 'jwt_vc_json',
        extra_property: 'should_stay',
        credential_definition: {
          type: ['one'],
          credentialSubject: {
            name: {
              mandatory: true,
            },
          },
        },
      },
      'w3c-jwt-vc-json-ld': {
        format: 'jwt_vc_json-ld',
        credential_definition: {
          type: ['one'],
          '@context': ['two'],
          credentialSubject: {
            name: {
              mandatory: true,
            },
          },
        },
      },
      'w3c-ldp-vc': {
        format: 'ldp_vc',
        credential_definition: {
          type: ['one'],
          '@context': ['two'],
          credentialSubject: {
            name: {
              mandatory: true,
            },
          },
        },
        credential_signing_alg_values_supported: ['EdDSA', 'ES256'],
      },
      'mso-mdoc': {
        format: 'mso_mdoc',
        doctype: 'some.doc.type',
        credential_signing_alg_values_supported: ['EdDSA', 'ES256'],
      },
    }

    const parseResult = v.safeParse(vCredentialIssuerMetadataDraft11To14, {
      credential_endpoint: 'https://credential-issuer.com/credential',
      credential_issuer: 'https://credential-issuer.com',
      credentials_supported,
      authorization_server: 'https://test.auth.com',
    })
    expect(parseResult).toStrictEqual({
      issues: undefined,
      output: {
        credential_endpoint: 'https://credential-issuer.com/credential',
        credential_issuer: 'https://credential-issuer.com',
        credential_configurations_supported,
        authorization_servers: ['https://test.auth.com'],
      },
      success: true,
      typed: true,
    })
  })
})
