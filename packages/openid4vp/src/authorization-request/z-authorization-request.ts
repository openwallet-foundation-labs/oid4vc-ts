import { URL, zHttpsUrl, zStringToJson } from '@openid4vc/utils'
import { z } from 'zod'
import { zClientMetadata } from '../models/z-client-metadata'
import { zVerifierAttestations } from '../models/z-verifier-attestations'

export const zOpenid4vpAuthorizationRequest = z
  .object({
    response_type: z.literal('vp_token'),
    client_id: z.string(),
    redirect_uri: zHttpsUrl.optional(),
    response_uri: zHttpsUrl.optional(),
    request_uri: zHttpsUrl.optional(),
    request_uri_method: z.optional(z.string()),
    response_mode: z.enum(['direct_post', 'direct_post.jwt']).optional(),
    nonce: z.string(),
    wallet_nonce: z.string().optional(),
    scope: z.string().optional(),
    presentation_definition: z
      .record(z.string(), z.any())
      // for backwards compat
      .or(zStringToJson)
      .optional(),
    presentation_definition_uri: zHttpsUrl.optional(),
    dcql_query: z
      .record(z.string(), z.any())
      // for backwards compat
      .or(zStringToJson)
      .optional(),
    client_metadata: zClientMetadata.optional(),
    client_metadata_uri: zHttpsUrl.optional(),
    state: z.string().optional(),
    transaction_data: z.array(z.base64url()).optional(),
    trust_chain: z.tuple([z.string()], z.string()).optional(),
    client_id_scheme: z
      .enum([
        'pre-registered',
        'redirect_uri',
        'entity_id',
        'did',
        'verifier_attestation',
        'x509_san_dns',
        'x509_san_uri',
        'x509_hash',
      ])
      .optional(),
    verifier_attestations: zVerifierAttestations.optional(),
    verifier_info: zVerifierAttestations.optional(),
  })
  .loose()

// Helps with parsing from an URI to a valid authorization request object
export const zOpenid4vpAuthorizationRequestFromUriParams = z
  .url()
  .transform((url): unknown => Object.fromEntries(new URL(url).searchParams))
  .pipe(
    z
      .object({
        presentation_definition: zStringToJson.optional(),
        client_metadata: zStringToJson.optional(),
        dcql_query: zStringToJson.optional(),
        transaction_data: zStringToJson.optional(),
        verifier_attestations: zStringToJson.optional(),
        verifier_info: zStringToJson.optional(),
      })
      .loose()
  )

export type Openid4vpAuthorizationRequest = z.infer<typeof zOpenid4vpAuthorizationRequest>
