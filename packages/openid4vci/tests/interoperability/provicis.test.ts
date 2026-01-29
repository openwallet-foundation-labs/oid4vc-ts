import { parseWithErrorHandling } from '@openid4vc/utils'
import { describe, expect, test } from 'vitest'
import { zCredentialIssuerMetadataWithDraftVersion } from '../../src/metadata/credential-issuer/z-credential-issuer-metadata'
import { findyProvicisCredentialIssuerMetadataJson } from './findy-provicis-credential-issuer-metadata-json'

describe('Interoperability | Provicis', () => {
  test('should correctly parse and validate credential issuer metadata', () => {
    // NOTE: the metadata uses `null` where it's not allowed. Keeping the test here with failing for now, we should
    // update this once the metadata has been updated.
    expect(() =>
      parseWithErrorHandling(zCredentialIssuerMetadataWithDraftVersion, findyProvicisCredentialIssuerMetadataJson)
    ).toThrowError(
      '✖ Expected object, received null at "credential_configurations_supported.https://alennusperuste.todiste.fi/credentials/v1/PensionCredential.proof_types_supported.jwt.key_attestations_required" or Expected array, received undefined at "credentials_supported"'
    )
  })
})
