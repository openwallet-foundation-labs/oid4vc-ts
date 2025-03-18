import { URL, zHttpsUrl } from '@openid4vc/utils'
import { z } from 'zod'
import { zClientMetadata } from '../models/z-client-metadata'

const zStringToJson = z.string().transform((string, ctx) => {
  try {
    return JSON.parse(string)
  } catch (error) {
    ctx.addIssue({
      code: 'custom',
      message: 'Expected a JSON string, but could not parse the string to JSON',
    })
    return z.NEVER
  }
})

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
      .record(z.any())
      // for backwards compat
      .or(zStringToJson)
      .optional(),
    presentation_definition_uri: zHttpsUrl.optional(),
    dcql_query: z
      .record(z.any())
      // for backwards compat
      .or(zStringToJson)
      .optional(),
    client_metadata: zClientMetadata.optional(),
    client_metadata_uri: zHttpsUrl.optional(),
    state: z.string().optional(),
    transaction_data: z.array(z.string().base64url()).optional(),
    trust_chain: z.unknown().optional(),
    client_id_scheme: z
      .enum([
        'pre-registered',
        'redirect_uri',
        'entity_id',
        'did',
        'verifier_attestation',
        'x509_san_dns',
        'x509_san_uri',
      ])
      .optional(),
  })
  .passthrough()

// Helps with parsing from an URI to a valid authorization request object
export const zOpenid4vpAuthorizationRequestFromUriParams = z
  .string()
  .url()
  .transform((url) => Object.fromEntries(new URL(url).searchParams))
  .pipe(
    z
      .object({
        presentation_definition: zStringToJson.optional(),
        client_metadata: zStringToJson.optional(),
        dcql_query: zStringToJson.optional(),
        transaction_data: zStringToJson.optional(),
      })
      .passthrough()
  )

export type Openid4vpAuthorizationRequest = z.infer<typeof zOpenid4vpAuthorizationRequest>
