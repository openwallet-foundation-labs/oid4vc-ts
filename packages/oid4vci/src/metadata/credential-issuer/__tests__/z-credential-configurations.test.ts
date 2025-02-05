import { describe, test } from 'vitest'
import type { CredentialConfigurationSupportedWithFormats } from '../../..'

describe('Credential Configuration Types', () => {
  // This is a type infer test, no actual code test
  test('should narrow types for format specific credential configurations', () => {
    const credentialConfiguration = {
      format: 'vc+sd-jwt',
      vct: 'hello',
    } as CredentialConfigurationSupportedWithFormats

    if (credentialConfiguration.format === 'vc+sd-jwt') {
      const vct: string = credentialConfiguration.vct
    }

    if (credentialConfiguration.format === 'jwt_vc_json-ld') {
      const context: string[] = credentialConfiguration.credential_definition['@context']
    }

    if (credentialConfiguration.format === 'ldp_vc') {
      const context: string[] = credentialConfiguration.credential_definition['@context']
    }

    if (credentialConfiguration.format === 'jwt_vc_json') {
      const type: string[] = credentialConfiguration.credential_definition.type
    }

    if (credentialConfiguration.format === 'mso_mdoc') {
      const doctype: string = credentialConfiguration.doctype
    }
  })
})
