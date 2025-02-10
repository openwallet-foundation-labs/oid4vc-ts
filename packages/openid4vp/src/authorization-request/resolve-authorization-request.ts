import { type CallbackContext, Oauth2Error } from '@openid4vc/oauth2'
import { parseWithErrorHandling } from '@openid4vc/utils'
import z from 'zod'
import { parseClientIdentifier } from '../client-identifier-scheme/parse-client-identifier-scheme'
import { verifyJarRequest } from '../jar/handle-jar-request/verify-jar-request'
import { type JarAuthRequest, zJarAuthRequest } from '../jar/z-jar-auth-request'
import { parseTransactionData } from '../transaction-data/parse-transaction-data'
import {
  type WalletVerificationOptions,
  validateOpenid4vpAuthorizationRequestPayload,
} from './validate-authorization-request'
import { type Openid4vpAuthorizationRequest, zOpenid4vpAuthorizationRequest } from './z-authorization-request'

export interface ResolveOpenid4vpAuthorizationRequestOptions {
  request: Openid4vpAuthorizationRequest | JarAuthRequest
  wallet?: WalletVerificationOptions
  callbacks: Pick<CallbackContext, 'verifyJwt' | 'decryptJwe' | 'getX509CertificateMetadata'>
}

export async function resolveOpenid4vpAuthorizationRequest(options: ResolveOpenid4vpAuthorizationRequestOptions) {
  const { request, wallet, callbacks } = options

  let authRequestPayload: Openid4vpAuthorizationRequest
  let jar: Awaited<ReturnType<typeof verifyJarRequest>> | undefined

  const parsed = parseWithErrorHandling(
    z.union([zOpenid4vpAuthorizationRequest, zJarAuthRequest]),
    request,
    'Invalid authorization request. Could not parse openid4vp authorization request as openid4vp or jar auth request.'
  )

  const parsedOpenid4vpAuthorizationRequest = zOpenid4vpAuthorizationRequest.safeParse(request)
  if (parsedOpenid4vpAuthorizationRequest.success) {
    authRequestPayload = parsedOpenid4vpAuthorizationRequest.data
  } else {
    const parsedJarAuthRequest = zJarAuthRequest.parse(parsed)
    jar = await verifyJarRequest({ jarRequestParams: parsedJarAuthRequest, callbacks, wallet })
    authRequestPayload = zOpenid4vpAuthorizationRequest.parse(jar.authRequestParams)
  }

  validateOpenid4vpAuthorizationRequestPayload({ params: authRequestPayload, walletVerificationOptions: wallet })

  const clientMeta = parseClientIdentifier({ request: authRequestPayload, jar, callbacks })

  let pex:
    | {
        presentation_definition: unknown
        presentation_definition_uri?: string
      }
    | undefined

  let dcql: { query: unknown } | undefined

  if (authRequestPayload.presentation_definition || authRequestPayload.presentation_definition_uri) {
    if (authRequestPayload.presentation_definition_uri) {
      throw new Oauth2Error('presentation_definition_uri is not supported')
    }
    pex = {
      presentation_definition: authRequestPayload.presentation_definition,
      presentation_definition_uri: authRequestPayload.presentation_definition_uri,
    }
  }

  if (authRequestPayload.dcql_query) {
    dcql = { query: authRequestPayload.dcql_query }
  }

  const transactionData = authRequestPayload.transaction_data
    ? parseTransactionData({ transactionData: authRequestPayload.transaction_data })
    : undefined

  return {
    transactionData,
    payload: authRequestPayload,
    jar,
    client: { ...clientMeta },
    pex,
    dcql,
  }
}

export type ResolvedOpenid4vpAuthRequest = Awaited<ReturnType<typeof resolveOpenid4vpAuthorizationRequest>>
