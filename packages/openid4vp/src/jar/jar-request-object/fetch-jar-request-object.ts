import { Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import {
  type BaseSchema,
  ContentType,
  type Fetch,
  createValibotFetcher,
  xWwwFormUrlEncodeObject,
} from '@openid4vc/utils'
import * as v from 'valibot'
import type { WalletMetadata } from '../../models/v-wallet-metadata'

/**
 * Fetch a request object and parse the response.
 * If you want to fetch the request object without providing wallet_metadata or wallet_nonce as defined in jar you can use the `fetchJarRequestObject` function.
 *
 * Returns validated request object if successful response
 * Throws error otherwise
 *
 * @throws {ValidationError} if successful response but validation of response failed
 * @throws {InvalidFetchResponseError} if no successful or 404 response
 * @throws {Error} if parsing json from response fails
 */
export async function fetchJarRequestObject<Schema extends BaseSchema>(
  requestUri: string,
  clientIdentifierScheme: string,
  method: 'GET' | 'POST',
  wallet: {
    metadata?: WalletMetadata
    nonce?: string
  },
  fetch?: Fetch
): Promise<v.InferOutput<Schema> | null> {
  const fetcher = createValibotFetcher(fetch)

  let requestBody = wallet.metadata ? { wallet_metadata: wallet.metadata, wallet_nonce: wallet.nonce } : undefined
  if (
    requestBody?.wallet_metadata?.request_object_signing_alg_values_supported &&
    clientIdentifierScheme === 'redirect_uri'
  ) {
    // This value indicates that the Client Identifier (without the prefix redirect_uri:) is the Verifier's Redirect URI (or Response URI when Response Mode direct_post is used). The Authorization Request MUST NOT be signed.
    const { request_object_signing_alg_values_supported, ...rest } = requestBody.wallet_metadata
    requestBody = { ...requestBody, wallet_metadata: { ...rest } }
  }

  const { result, response } = await fetcher(v.string(), ContentType.OAuthRequestObjectJwt, requestUri, {
    method,
    headers: {
      Accept: `${ContentType.OAuthRequestObjectJwt}, ${ContentType.Jwt};q=0.9`,
      'Content-Type': ContentType.XWwwFormUrlencoded,
    },
    body: method === 'POST' ? xWwwFormUrlEncodeObject(wallet.metadata ?? {}) : undefined,
  })

  if (!response.ok) {
    throw new Oauth2ServerErrorResponseError({
      error_description: `Fetching request_object from request_uri '${requestUri}' failed with status code '${response.status}'.`,
      error: 'invalid_request_uri',
    })
  }

  if (!result || !result.success) {
    throw new Oauth2ServerErrorResponseError({
      error_description: `Parsing request_object from request_uri '${requestUri}' failed.`,
      error: 'invalid_request_object',
    })
  }

  return result.output
}
