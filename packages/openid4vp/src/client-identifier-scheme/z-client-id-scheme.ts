import { getGlobalConfig } from '@openid4vc/utils'
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

export const zClientIdToClientIdScheme = z.union(
  [
    z
      .string({ message: 'client_id MUST be a string' })
      .includes(':')
      .transform((clientId) => {
        const clientIdScheme = clientId.split(':')[0]
        return clientIdScheme === 'http' && getGlobalConfig().allowInsecureUrls ? 'https' : clientIdScheme
      })
      .pipe(zClientIdScheme.exclude(['pre-registered'])),
    z
      .string()
      .refine((clientId) => clientId.includes(':') === false)
      .transform(() => 'pre-registered' as const),
  ],
  {
    message: `client_id must either start with a known prefix followed by ':' or contain no ':'. Known prefixes are ${zClientIdScheme.exclude(['pre-registered']).options.join(', ')}`,
  }
)

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

export const zLegacyClientIdSchemeToClientIdScheme = zLegacyClientIdScheme
  .optional()
  .default('pre-registered')
  .transform((clientIdScheme) => (clientIdScheme === 'entity_id' ? 'https' : clientIdScheme))
