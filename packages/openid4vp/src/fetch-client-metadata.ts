import { Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { type BaseSchema, ContentType, type Fetch, createZodFetcher } from '@openid4vc/utils'
import type { z } from 'zod'
import { zWalletMetadata } from './models/z-wallet-metadata'

export async function fetchClientMetadata<Schema extends BaseSchema>(options: {
  clientMetadataUri: string
  fetch?: Fetch
}): Promise<z.infer<Schema> | null> {
  const { fetch, clientMetadataUri } = options
  const fetcher = createZodFetcher(fetch)

  const { result, response } = await fetcher(zWalletMetadata, ContentType.Json, clientMetadataUri, {
    method: 'GET',
    headers: {
      Accept: ContentType.Json,
    },
  })

  if (!response.ok) {
    throw new Oauth2ServerErrorResponseError({
      error_description: `Fetching client metadata from '${clientMetadataUri}' failed with status code '${response.status}'.`,
      error: Oauth2ErrorCodes.InvalidRequestUri,
    })
  }

  if (!result || !result.success) {
    throw new Oauth2ServerErrorResponseError({
      error_description: `Parsing client metadata from '${clientMetadataUri}' failed.`,
      error: Oauth2ErrorCodes.InvalidRequestObject,
    })
  }

  return result.data
}
