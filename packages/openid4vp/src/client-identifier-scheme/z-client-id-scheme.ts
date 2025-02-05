import { z } from 'zod'

export const zClientIdScheme = z.enum([
  'pre-registered',
  'redirect_uri',
  'https',
  'verifier_attestation',
  'did',
  'x509_san_dns',
  'x509_san_uri',
  'web-origin',
])

export type ClientIdScheme = z.infer<typeof zClientIdScheme>
