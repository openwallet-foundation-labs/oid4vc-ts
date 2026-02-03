import { describe, expect, test } from 'vitest'
import type { $ZodIssueInvalidUnion } from 'zod/v4/core'
import { paradymDraft13 } from '../../../__tests__/__fixtures__/paradym'
import {
  zCredentialConfigurationSupportedWithFormats,
  zCredentialIssuerMetadata,
  zCredentialIssuerMetadataDraft11ToV1,
} from '../z-credential-issuer-metadata'

describe('Credential Issuer Metadata', () => {
  test('should parse credential configurations supported with format', () => {
    // Correct: sd-jwt with vct
    expect(
      zCredentialConfigurationSupportedWithFormats.safeParse({
        format: 'vc+sd-jwt',
        // vct should be required if format is vc+sd-jwt
        vct: 'SD_JWT_VC_example_in_OpenID4VCI',
      })
    ).toStrictEqual({
      data: expect.objectContaining({}),
      success: true,
    })

    const parseResult = zCredentialConfigurationSupportedWithFormats.safeParse({
      format: 'vc+sd-jwt',
      // vct should be required if format is vc+sd-jwt
      // vct: 'SD_JWT_VC_example_in_OpenID4VCI',
    })

    // Incorrect: sd-jwt without vct
    expect(parseResult.success).toBe(false)
    expect((parseResult.error?.issues[0] as $ZodIssueInvalidUnion)?.errors[0][0]).toEqual({
      code: 'invalid_type',
      // FIXME(vc+sd-jwt): fix expected to be 'string' when dropping support for legacy vc+sd-jwt format.
      expected: 'object',
      path: ['credential_definition'],
      message: 'expected object, received undefined',
    })

    // Correct: mso mdoc with doctype
    expect(
      zCredentialConfigurationSupportedWithFormats.safeParse({
        format: 'mso_mdoc',
        // doctype should be required if format is mso_mdoc
        doctype: 'org.iso.18013.5.1.mDL',
      })
    ).toStrictEqual({
      data: expect.objectContaining({}),
      success: true,
    })

    // Incorrect: mso mdoc without doctype
    const parseResultMdoc = zCredentialConfigurationSupportedWithFormats.safeParse({
      format: 'mso_mdoc',
      // doctype should be required if format is mso_mdoc
      // doctype: 'org.iso.18013.5.1.mDL',
    })
    expect(parseResultMdoc.success).toEqual(false)
    expect(parseResultMdoc.error?.issues[0]).toMatchObject({
      code: 'invalid_union',
      message: 'Invalid input',
      path: [],
    })

    expect((parseResultMdoc.error?.issues[0] as $ZodIssueInvalidUnion).errors[0]).toMatchObject([
      {
        code: 'invalid_type',
        expected: 'string',
        path: ['doctype'],
        message: 'expected string, received undefined',
      },
    ])
  })

  test('parse draft 13 credential issuer metadata', () => {
    const parseResult = zCredentialIssuerMetadata.safeParse(paradymDraft13.credentialIssuerMetadata)
    expect(parseResult).toStrictEqual({
      data: paradymDraft13.credentialIssuerMetadata,
      success: true,
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
        format: 'dc+sd-jwt',
        vct: 'vct-test-id',
        credential_metadata: {
          display: [
            {
              name: 'hello',
              logo: {
                uri: 'https://logo.com',
              },
            },
          ],
        },
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
        // For mso_mdoc, JOSE algorithms are transformed to COSE numbers
        // EdDSA -> -19 (Ed25519), ES256 -> -9 (ESP256)
        credential_signing_alg_values_supported: [-19, -9],
      },
    }

    const parseResult = zCredentialIssuerMetadataDraft11ToV1.safeParse({
      credential_endpoint: 'https://credential-issuer.com/credential',
      credential_issuer: 'https://credential-issuer.com',
      credentials_supported,
      authorization_server: 'https://test.auth.com',
    })
    expect(parseResult).toStrictEqual({
      data: {
        credential_endpoint: 'https://credential-issuer.com/credential',
        credential_issuer: 'https://credential-issuer.com',
        credential_configurations_supported,
        authorization_servers: ['https://test.auth.com'],
      },
      success: true,
    })
  })
})
