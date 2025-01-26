import type { CallbackContext } from '@openid4vc/oauth2'
import * as v from 'valibot'
import { parseClientIdentifier } from '../client-identifier-scheme/parse-client-identifier-scheme'
import { verifyJarRequest } from '../jar/handle-jar-request/verify-jar-request.js'
import { type JarAuthRequest, vJarAuthRequest } from '../jar/v-jar-auth-request'
import type { WalletMetadata } from '../models/v-wallet-metadata'
import { parseTransactionData } from '../transaction-data/parse-transaction-data'
import { type Openid4vpAuthRequest, vOpenid4vpAuthRequest } from './v-openid4vp-auth-request'
import { validateOpenid4vpAuthRequestParams } from './validate-openid4vp-auth-request'

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

  if (v.is(vJarAuthRequest, params)) {
    jar = await verifyJarRequest({ jarRequestParams: params, callbacks, wallet })
    authRequestParams = v.parse(vOpenid4vpAuthRequest, jar.authRequestParams)
  } else {
    authRequestParams = params
  }

  validateOpenid4vpAuthRequestParams(authRequestParams, { wallet: options.wallet })

  const clientMeta = parseClientIdentifier({ request: authRequestParams, jar, callbacks })

  let pex:
    | {
        presentation_definition: unknown
        presentation_definition_uri?: string
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

  const transactionData = authRequestParams.transaction_data
    ? parseTransactionData(authRequestParams.transaction_data)
    : undefined

  return {
    transactionData,
    payload: authRequestParams,
    jar,
    client: { ...clientMeta },
    pex,
  }
}

export type VerifiedOpenid4vpAuthRequest = Awaited<ReturnType<typeof verifyOpenid4vpAuthRequest>>
