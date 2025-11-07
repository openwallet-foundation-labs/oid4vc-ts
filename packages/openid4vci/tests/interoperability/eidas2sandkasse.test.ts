import fs from 'node:fs'
import path from 'node:path'
import { describe, expect, test } from 'vitest'
import { zCredentialIssuerMetadataWithDraftVersion } from '../../src/metadata/credential-issuer/z-credential-issuer-metadata'

// https://utsteder.test.eidas2sandkasse.net/.well-known/openid-credential-issuer
const eidas2sandkasseCredentialIssuerMetadata = JSON.parse(
  fs.readFileSync(path.join(__dirname, './eidas2sandkasse-credential-issuer-metadata.json'), { encoding: 'utf-8' })
)

describe('Interoperability | eidas2sandkasse.net', () => {
  test('should correctly parse and validate credential issuer metadata', () => {
    const result = zCredentialIssuerMetadataWithDraftVersion.safeParse(eidas2sandkasseCredentialIssuerMetadata)

    expect(result).toEqual({
      success: true,
      data: {
        credentialIssuerMetadata: eidas2sandkasseCredentialIssuerMetadata,
        originalDraftVersion: 'V1',
      },
    })
  })
})
