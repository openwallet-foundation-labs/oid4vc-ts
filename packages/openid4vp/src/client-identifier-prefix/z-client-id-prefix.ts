import { getGlobalConfig } from '@openid4vc/utils'
import { z } from 'zod'

export const zClientIdPrefix = z.enum([
  'pre-registered',
  'redirect_uri',
  'verifier_attestation',

  'https', // pre draft 26
  'openid_federation', // from draft 26

  'did', // pre draft 26
  'decentralized_identifier', // from draft 26

  'x509_san_uri', // pre-draft 25
  'x509_hash', // from draft 25

  'x509_san_dns',

  'origin', // from draft 25
  'web-origin', // pre-draft 25
])

export const zUniformClientIdPrefix = zClientIdPrefix.exclude(['did', 'https', 'web-origin'])

export type ClientIdPrefix = z.infer<typeof zClientIdPrefix>
export type UniformClientIdPrefix = z.infer<typeof zUniformClientIdPrefix>

export const zClientIdToClientIdPrefixAndIdentifier = z.union(
  [
    z
      .string({ message: 'client_id MUST be a string' })
      .includes(':')
      .transform((clientId) => {
        const colonIndex = clientId.indexOf(':')
        const clientIdPrefix = clientId.slice(0, colonIndex)
        const clientIdIdentifier = clientId.slice(colonIndex + 1)

        // If we allow http, we parse it as https
        if (clientIdPrefix === 'http' && getGlobalConfig().allowInsecureUrls) {
          return ['https', clientId]
        }

        if (clientIdPrefix === 'did' || clientIdPrefix === 'http' || clientIdPrefix === 'https') {
          return [clientIdPrefix, clientId]
        }

        return [clientIdPrefix, clientIdIdentifier]
      })
      .pipe(z.tuple([zClientIdPrefix.exclude(['pre-registered']), z.string()])),
    z
      .string()
      .refine((clientId) => clientId.includes(':') === false)
      .transform((clientId) => ['pre-registered', clientId] as const),
  ],
  {
    message: `client_id must either start with a known prefix followed by ':' or contain no ':'. Known prefixes are ${zClientIdPrefix.exclude(['pre-registered']).options.join(', ')}`,
  }
)

export const zClientIdPrefixToUniform = zClientIdPrefix.transform((prefix) =>
  prefix === 'did'
    ? 'decentralized_identifier'
    : prefix === 'https'
      ? 'openid_federation'
      : prefix === 'web-origin'
        ? 'origin'
        : prefix
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

export const zLegacyClientIdSchemeToClientIdPrefix = zLegacyClientIdScheme
  .optional()
  .default('pre-registered')
  .transform((clientIdScheme) =>
    clientIdScheme === 'entity_id'
      ? 'openid_federation'
      : clientIdScheme === 'did'
        ? 'decentralized_identifier'
        : clientIdScheme
  )
