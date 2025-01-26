import type { JwkSet } from '@openid4vc/oauth2'
import * as v from 'valibot'
import { type JarmClientMetadata, JarmClientMetadataParsed } from './metadata/v-jarm-dcr-metadata'

export function extractJwksFromClientMetadata(clientMetadata: JarmClientMetadata & { jwks: JwkSet }) {
  const parsed = v.parse(JarmClientMetadataParsed, clientMetadata)

  const encryptionAlg = parsed.client_metadata.authorization_encrypted_response_enc
  const signingAlg = parsed.client_metadata.authorization_signed_response_alg

  const encJwk =
    clientMetadata.jwks.keys.find((key) => key.use === 'enc' && key.alg === encryptionAlg) ??
    clientMetadata.jwks.keys.find((key) => key.use === 'enc')

  const sigJwk =
    clientMetadata.jwks.keys.find((key) => key.use === 'sig' && key.alg === signingAlg) ??
    clientMetadata.jwks.keys.find((key) => key.use === 'sig')

  return { encJwk, sigJwk }
}
