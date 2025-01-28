import { expect, test } from 'vitest'
import { vMsoMdocCredentialIssuerMetadata, vMsoMdocFormatIdentifier } from '../v-mso-mdoc'

test('should parse mso mdoc format identifier', () => {
  expect(vMsoMdocFormatIdentifier.safeParse('mso_mdoc')).toStrictEqual({
    data: 'mso_mdoc',
    success: true,
  })

  expect(vMsoMdocFormatIdentifier.safeParse('mso_mdoc2')).toStrictEqual({
    error: expect.any(Error),
    success: false,
  })
})

test('should parse mso mdoc credential issuer metadata', () => {
  expect(
    vMsoMdocCredentialIssuerMetadata.safeParse({
      format: 'mso_mdoc',
      doctype: 'org.iso.18013.5.1.mDL',
      cryptographic_binding_methods_supported: ['cose_key'],
      credential_signing_alg_values_supported: ['ES256', 'ES384', 'ES512'],
      display: [
        {
          name: 'Mobile Driving License',
          locale: 'en-US',
          logo: {
            uri: 'https://state.example.org/public/mdl.png',
            alt_text: 'state mobile driving license',
          },
          background_color: '#12107c',
          text_color: '#FFFFFF',
        },
        {
          name: 'モバイル運転免許証',
          locale: 'ja-JP',
          logo: {
            uri: 'https://state.example.org/public/mdl.png',
            alt_text: '米国州発行のモバイル運転免許証',
          },
          background_color: '#12107c',
          text_color: '#FFFFFF',
        },
      ],
      claims: {
        'org.iso.18013.5.1': {
          given_name: {
            display: [
              {
                name: 'Given Name',
                locale: 'en-US',
              },
              {
                name: '名前',
                locale: 'ja-JP',
              },
            ],
          },
          family_name: {
            display: [
              {
                name: 'Surname',
                locale: 'en-US',
              },
            ],
          },
          birth_date: {
            mandatory: true,
          },
        },
        'org.iso.18013.5.1.aamva': {
          organ_donor: {},
        },
      },
    })
  ).toStrictEqual({
    data: expect.objectContaining({}),
    success: true,
  })
})
