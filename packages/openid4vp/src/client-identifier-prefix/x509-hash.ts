import { type CallbackContext, HashAlgorithm } from '@openid4vc/oauth2'
import { decodeBase64, encodeToBase64Url } from '@openid4vc/utils'

export async function calculateX509HashClientIdPrefixValue({
  x509Certificate,
  hash,
}: {
  /**
   * DER encoded x509 certificate. Either encoded as base64 or directly as Uint8Array
   */
  x509Certificate: string | Uint8Array

  hash: CallbackContext['hash']
}) {
  return encodeToBase64Url(
    await hash(
      typeof x509Certificate === 'string' ? decodeBase64(x509Certificate) : x509Certificate,
      HashAlgorithm.Sha256
    )
  )
}
