import * as v from 'valibot'
import { expect, test } from 'vitest'
import { vCredentialConfigurationSupportedWithFormats } from '../v-credential-issuer-metadata'

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
