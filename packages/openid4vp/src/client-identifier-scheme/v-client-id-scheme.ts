import * as v from 'valibot'

export const vClientIdScheme = v.picklist([
  'pre-registered',
  'redirect_uri',
  'https',
  'verifier_attestation',
  'did',
  'x509_san_dns',
  'x509_san_uri',
  'web-origin',
])

export type ClientIdScheme = v.InferOutput<typeof vClientIdScheme>
