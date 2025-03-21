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

export const zLegacyClientIdScheme = z.enum([
  'pre-registered',
  'redirect_uri',
  'entity_id',
  'did',
  'verifier_attestation',
  'x509_san_dns',
  'x509_san_uri',
])

export type LegacyClientIdScheme = z.infer<typeof zLegacyClientIdScheme>
