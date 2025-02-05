import type { CallbackContext } from '@openid4vc/oauth2'
import { parseClientIdentifier } from '../client-identifier-scheme/parse-client-identifier-scheme'
import { verifyJarRequest } from '../jar/handle-jar-request/verify-jar-request'
import { type JarAuthRequest, zJarAuthRequest } from '../jar/z-jar-auth-request'
import type { WalletMetadata } from '../models/z-wallet-metadata'
import { parseTransactionData } from '../transaction-data/parse-transaction-data'
import { validateOpenid4vpAuthRequestParams } from './validate-openid4vp-auth-request'
import { type Openid4vpAuthRequest, zOpenid4vpAuthRequest } from './z-openid4vp-auth-request'

export async function verifyOpenid4vpAuthRequest(
  params: Openid4vpAuthRequest | JarAuthRequest,
  options: {
    wallet?: {
      nonce?: string
      metadata?: WalletMetadata
    }
    callbacks: Pick<CallbackContext, 'verifyJwt' | 'decryptJwt' | 'getX509SanDnsNames' | 'getX509SanUriNames'>
  }
) {
  const { wallet, callbacks } = options

  let authRequestParams: Openid4vpAuthRequest
  let jar: Awaited<ReturnType<typeof verifyJarRequest>> | undefined

  const parsedJarAuthRequest = zJarAuthRequest.safeParse(params)
  if (parsedJarAuthRequest.success) {
    jar = await verifyJarRequest({ jarRequestParams: parsedJarAuthRequest.data, callbacks, wallet })
    authRequestParams = zOpenid4vpAuthRequest.parse(jar.authRequestParams)
  } else {
    authRequestParams = params as Openid4vpAuthRequest
  }

  validateOpenid4vpAuthRequestParams(authRequestParams, { wallet: options.wallet })

  const clientMeta = parseClientIdentifier({ request: authRequestParams, jar, callbacks })

  let pex:
    | {
        presentation_definition: unknown
        presentation_definition_uri?: string
      }
    | undefined

  let dcql:
    | {
        query: unknown
      }
    | undefined

  if (authRequestParams.presentation_definition || authRequestParams.presentation_definition_uri) {
    if (authRequestParams.presentation_definition_uri) {
      throw new Error('presentation_definition_uri is not supported')
    }
    pex = {
      presentation_definition: authRequestParams.presentation_definition,
      presentation_definition_uri: authRequestParams.presentation_definition_uri,
    }
  }

  if (authRequestParams.dcql_query) {
    dcql = {
      query: authRequestParams.dcql_query,
    }
  }

  const transactionData = authRequestParams.transaction_data
    ? parseTransactionData(authRequestParams.transaction_data)
    : undefined

  return {
    transactionData,
    payload: authRequestParams,
    jar,
    client: { ...clientMeta },
    pex,
    dcql,
  }
}

export type VerifiedOpenid4vpAuthRequest = Awaited<ReturnType<typeof verifyOpenid4vpAuthRequest>>
