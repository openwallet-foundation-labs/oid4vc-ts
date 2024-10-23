import * as v from 'valibot'
import { expect, test } from 'vitest'
import { vSdJwtVcCredentialIssuerMetadata, vSdJwtVcFormatIdentifier } from '../v-sd-jwt-vc'

test('should parse sd-jwt-vc format identifier', () => {
  expect(v.safeParse(vSdJwtVcFormatIdentifier, 'vc+sd-jwt')).toStrictEqual({
    issues: undefined,
    output: 'vc+sd-jwt',
    success: true,
    typed: true,
  })

  expect(v.safeParse(vSdJwtVcFormatIdentifier, 'vc+sd-jwt2')).toStrictEqual({
    issues: expect.any(Array),
    output: 'vc+sd-jwt2',
    success: false,
    typed: false,
  })
})

test('should parse sd-jwt-vc credential issuer metadata', () => {
  expect(
    v.safeParse(vSdJwtVcCredentialIssuerMetadata, {
      format: 'vc+sd-jwt',
      scope: 'SD_JWT_VC_example_in_OpenID4VCI',
      cryptographic_binding_methods_supported: ['jwk'],
      credential_signing_alg_values_supported: ['ES256'],
      display: [
        {
          name: 'IdentityCredential',
          logo: {
            uri: 'https://university.example.edu/public/logo.png',
            alt_text: 'a square logo of a university',
          },
          locale: 'en-US',
          background_color: '#12107c',
          text_color: '#FFFFFF',
        },
      ],
      proof_types_supported: {
        jwt: {
          proof_signing_alg_values_supported: ['ES256'],
        },
      },
      vct: 'SD_JWT_VC_example_in_OpenID4VCI',
      claims: {
        given_name: {
          display: [
            {
              name: 'Given Name',
              locale: 'en-US',
            },
            {
              name: 'Vorname',
              locale: 'de-DE',
            },
          ],
        },
        family_name: {
          display: [
            {
              name: 'Surname',
              locale: 'en-US',
            },
            {
              name: 'Nachname',
              locale: 'de-DE',
            },
          ],
        },
        email: {},
        phone_number: {},
        address: {
          street_address: {},
          locality: {},
          region: {},
          country: {},
        },
        birthdate: {},
        is_over_18: {},
        is_over_21: {},
        is_over_65: {},
      },
    })
  ).toStrictEqual({
    issues: undefined,
    output: expect.objectContaining({}),
    success: true,
    typed: true,
  })
})
