import { jwaSignatureAlgorithmArrayToFullySpecifiedCoseAlgorithmArray } from '@openid4vc/oauth2'
import { describe, expect, test } from 'vitest'
import { zCredentialIssuerMetadataWithDraftVersion } from '../../src/metadata/credential-issuer/z-credential-issuer-metadata'
import { eidas2sandkasseCredentialIssuerMetadataJson } from './eidas2sandkasse-credential-issuer-metadata-json'

// credential_signing_alg_values_supported for mso_mdoc uses strings, this is non-compliant with 1.0
const eidas2sandkasseCredentialIssuerMetadataJsonFixes = {
  ...eidas2sandkasseCredentialIssuerMetadataJson,
  credential_configurations_supported: Object.fromEntries(
    Object.entries(eidas2sandkasseCredentialIssuerMetadataJson.credential_configurations_supported).map(
      ([credentialConfigurationId, credentialConfiguration]) => [
        credentialConfigurationId,
        credentialConfiguration.format === 'mso_mdoc'
          ? {
              ...credentialConfiguration,
              credential_signing_alg_values_supported: jwaSignatureAlgorithmArrayToFullySpecifiedCoseAlgorithmArray(
                credentialConfiguration.credential_signing_alg_values_supported
              ),
            }
          : credentialConfiguration,
      ]
    )
  ),
}

describe('Interoperability | eidas2sandkasse.net', () => {
  test('should correctly parse and validate credential issuer metadata', () => {
    const result = zCredentialIssuerMetadataWithDraftVersion.safeParse(eidas2sandkasseCredentialIssuerMetadataJsonFixes)

    expect(result).toEqual({
      success: true,
      data: {
        credentialIssuerMetadata: eidas2sandkasseCredentialIssuerMetadataJsonFixes,
        originalDraftVersion: 'V1',
      },
    })
  })
})
