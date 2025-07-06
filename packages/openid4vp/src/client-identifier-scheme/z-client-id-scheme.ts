import { getGlobalConfig } from '@openid4vc/utils'
import { z } from 'zod'

export const zClientIdScheme = z.enum([
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
  'web-origin',
])

export const zUniformClientIdScheme = zClientIdScheme.exclude(['did', 'https'])

export type ClientIdScheme = z.infer<typeof zClientIdScheme>
export type UniformClientIdSchema = z.infer<typeof zUniformClientIdScheme>

export const zClientIdToClientIdSchemeAndIdentifier = z.union(
  [
    z
      .string({ message: 'client_id MUST be a string' })
      .includes(':')
      .transform((clientId) => {
        const colonIndex = clientId.indexOf(':')
        const clientIdScheme = clientId.slice(0, colonIndex)
        const clientIdIdentifier = clientId.slice(colonIndex + 1)

        // If we allow http, we parse it as https
        if (clientIdScheme === 'http' && getGlobalConfig().allowInsecureUrls) {
          return ['https', clientId]
        }

        if (clientIdScheme === 'did' || clientIdScheme === 'http' || clientIdScheme === 'https') {
          return [clientIdScheme, clientId]
        }

        return [clientIdScheme, clientIdIdentifier]
      })
      .pipe(z.tuple([zClientIdScheme.exclude(['pre-registered']), z.string()])),
    z
      .string()
      .refine((clientId) => clientId.includes(':') === false)
      .transform((clientId) => ['pre-registered', clientId] as const),
  ],
  {
    message: `client_id must either start with a known prefix followed by ':' or contain no ':'. Known prefixes are ${zClientIdScheme.exclude(['pre-registered']).options.join(', ')}`,
  }
)

export const zClientIdSchemeToUniform = zClientIdScheme.transform((scheme) =>
  scheme === 'did' ? 'decentralized_identifier' : scheme === 'https' ? 'openid_federation' : scheme
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
  .transform((clientIdScheme) =>
    clientIdScheme === 'entity_id'
      ? 'openid_federation'
      : clientIdScheme === 'did'
        ? 'decentralized_identifier'
        : clientIdScheme
  )
