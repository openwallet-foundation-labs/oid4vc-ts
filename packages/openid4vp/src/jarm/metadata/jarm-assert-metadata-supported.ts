import { Oauth2Error } from '@openid4vc/oauth2'
import type { JarmServerMetadata } from './z-jarm-authorization-server-metadata'
import { type JarmClientMetadata, zJarmClientMetadataParsed } from './z-jarm-client-metadata'

interface AssertValueSupported<T> {
  supported: T[]
  actual: T
  errorMessage: string
}

function assertValueSupported<T>(options: AssertValueSupported<T>): T {
  const { errorMessage, supported, actual } = options
  const intersection = supported.find((value) => value === actual)

  if (!intersection) {
    throw new Oauth2Error(errorMessage)
  }

  return intersection
}

export function jarmAssertMetadataSupported(options: {
  clientMetadata: JarmClientMetadata
  serverMetadata: JarmServerMetadata
}) {
  const { clientMetadata, serverMetadata } = options
  const parsedClientMetadata = zJarmClientMetadataParsed.parse(clientMetadata)

  if (parsedClientMetadata.type === 'sign_encrypt' || parsedClientMetadata.type === 'encrypt') {
    if (serverMetadata.authorization_encryption_alg_values_supported) {
      assertValueSupported({
        supported: serverMetadata.authorization_encryption_alg_values_supported,
        actual: parsedClientMetadata.client_metadata.authorization_encrypted_response_alg,
        errorMessage: 'Invalid authorization_encryption_alg',
      })
    }

    if (serverMetadata.authorization_encryption_enc_values_supported) {
      assertValueSupported({
        supported: serverMetadata.authorization_encryption_enc_values_supported,
        actual: parsedClientMetadata.client_metadata.authorization_encrypted_response_enc,
        errorMessage: 'Invalid authorization_encryption_enc',
      })
    }
  }

  if (
    serverMetadata.authorization_signing_alg_values_supported &&
    (parsedClientMetadata.type === 'sign' || parsedClientMetadata.type === 'sign_encrypt')
  ) {
    assertValueSupported({
      supported: serverMetadata.authorization_signing_alg_values_supported,
      actual: parsedClientMetadata.client_metadata.authorization_signed_response_alg,
      errorMessage: 'Invalid authorization_signed_response_alg',
    })
  }

  return parsedClientMetadata
}
