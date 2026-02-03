import { Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { ContentType, createZodFetcher, type Fetch } from '@openid4vc/utils'
import { type ClientMetadata, zClientMetadata } from './models/z-client-metadata'

export async function fetchClientMetadata(options: {
  clientMetadataUri: string
  fetch?: Fetch
}): Promise<ClientMetadata> {
  const { fetch, clientMetadataUri } = options
  const fetcher = createZodFetcher(fetch)

  const { result, response } = await fetcher(zClientMetadata, ContentType.Json, clientMetadataUri, {
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
