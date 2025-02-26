import type { JwkSet } from '@openid4vc/oauth2'
import { type JarmClientMetadata, zJarmClientMetadataParsed } from './metadata/z-jarm-client-metadata'

export function extractJwksFromClientMetadata(clientMetadata: JarmClientMetadata & { jwks: JwkSet }) {
  const parsed = zJarmClientMetadataParsed.parse(clientMetadata)

  const encryptionAlg = parsed.client_metadata.authorization_encrypted_response_enc
  const signingAlg = parsed.client_metadata.authorization_signed_response_alg

  const encJwk =
    clientMetadata.jwks.keys.find((key) => key.use === 'enc' && key.alg === encryptionAlg) ??
    clientMetadata.jwks.keys.find((key) => key.use === 'enc') ??
    // fallback, take first key. HAIP does not specify requirement on enc
    clientMetadata.jwks.keys?.[0]

  const sigJwk =
    clientMetadata.jwks.keys.find((key) => key.use === 'sig' && key.alg === signingAlg) ??
    clientMetadata.jwks.keys.find((key) => key.use === 'sig') ??
    // falback, take first key
    clientMetadata.jwks.keys?.[0]

  return { encJwk, sigJwk }
}
