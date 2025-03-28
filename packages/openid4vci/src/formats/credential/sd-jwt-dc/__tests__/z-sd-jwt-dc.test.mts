import { expect, test } from 'vitest'
import { zSdJwtDcCredentialIssuerMetadata, zSdJwtDcFormatIdentifier } from '../z-sd-jwt-dc.js'

test('should parse sd-jwt-dc format identifier', () => {
  expect(zSdJwtDcFormatIdentifier.safeParse('dc+sd-jwt')).toStrictEqual({
    data: 'dc+sd-jwt',
    success: true,
  })

  expect(zSdJwtDcFormatIdentifier.safeParse('dc+sd-jwt2')).toStrictEqual({
    error: expect.any(Error),
    success: false,
  })
})

test('should parse sd-jwt-dc credential issuer metadata', () => {
  expect(
    zSdJwtDcCredentialIssuerMetadata.safeParse({
      format: 'dc+sd-jwt',
      scope: 'SD_JWT_DC_example_in_OpenID4VCI',
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
      vct: 'SD_JWT_DC_example_in_OpenID4VCI',
      claims: [
        {
          path: ['given_name'],
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
        {
          path: ['family_name'],
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
        {
          path: ['email'],
        },
      ],
    })
  ).toStrictEqual({
    data: expect.objectContaining({}),
    success: true,
  })
})
