import { type CallbackContext, Oauth2Error } from '@openid4vc/oauth2'
import { parseWithErrorHandling } from '@openid4vc/utils'
import z from 'zod'
import {
  type ParsedClientIdentifier,
  parseClientIdentifier,
} from '../client-identifier-scheme/parse-client-identifier-scheme'
import { type VerifiedJarRequest, verifyJarRequest } from '../jar/handle-jar-request/verify-jar-request'
import { type JarAuthRequest, isJarAuthRequest, zJarAuthRequest } from '../jar/z-jar-auth-request'
import { parseTransactionData } from '../transaction-data/parse-transaction-data'
import type { TransactionData } from '../transaction-data/z-transaction-data'
import {
  type WalletVerificationOptions,
  validateOpenid4vpAuthorizationRequestPayload,
} from './validate-authorization-request'
import { validateOpenid4vpAuthorizationRequestDcApiPayload } from './validate-authorization-request-dc-api'
import { type Openid4vpAuthorizationRequest, zOpenid4vpAuthorizationRequest } from './z-authorization-request'
import {
  type Openid4vpAuthorizationRequestDcApi,
  isOpenid4vpAuthorizationRequestDcApi,
  zOpenid4vpAuthorizationRequestDcApi,
} from './z-authorization-request-dc-api'

export interface ResolveOpenid4vpAuthorizationRequestOptions {
  request: Openid4vpAuthorizationRequest | JarAuthRequest
  wallet?: WalletVerificationOptions
  origin?: string
  omitOriginValidation?: boolean
  callbacks: Pick<CallbackContext, 'verifyJwt' | 'decryptJwe' | 'getX509CertificateMetadata'>
}

export type ResolvedOpenid4vpAuthRequest = {
  transactionData?: TransactionData
  payload: Openid4vpAuthorizationRequest | Openid4vpAuthorizationRequestDcApi
  jar: VerifiedJarRequest | undefined
  client: ParsedClientIdentifier
  pex?: {
    presentation_definition: unknown
    presentation_definition_uri?: string
  }
  dcql?: { query: unknown } | undefined
}
export async function resolveOpenid4vpAuthorizationRequest(
  options: ResolveOpenid4vpAuthorizationRequestOptions
): Promise<ResolvedOpenid4vpAuthRequest> {
  const { request, wallet, callbacks, origin, omitOriginValidation } = options

  let authRequestPayload:
    | Openid4vpAuthorizationRequest
    | (Openid4vpAuthorizationRequestDcApi & { presentation_definition_uri?: never })
  let jar: Awaited<ReturnType<typeof verifyJarRequest>> | undefined

  const parsed = parseWithErrorHandling(
    z.union([zOpenid4vpAuthorizationRequestDcApi, zOpenid4vpAuthorizationRequest, zJarAuthRequest]),
    request,
    'Invalid authorization request. Could not parse openid4vp authorization request as openid4vp or jar auth request.'
  )

  if (isJarAuthRequest(request)) {
    const parsedJarAuthRequest = parseWithErrorHandling(
      zJarAuthRequest,
      parsed,
      'Invalid authorization request. Could not parse jar auth request.'
    )
    jar = await verifyJarRequest({ jarRequestParams: parsedJarAuthRequest, callbacks, wallet })
    authRequestPayload = parseOpenid4vpAuthorizationRequestPayload({
      request: jar.authRequestParams,
      wallet,
      jar: true,
      origin,
      omitOriginValidation,
    })
  } else {
    authRequestPayload = parseOpenid4vpAuthorizationRequestPayload({
      request,
      wallet,
      jar: false,
      origin,
      omitOriginValidation,
    })
  }

  const clientMeta = parseClientIdentifier({ request: authRequestPayload, jar, callbacks, origin })

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

function parseOpenid4vpAuthorizationRequestPayload(options: {
  request: Record<string, unknown>
  wallet?: WalletVerificationOptions
  jar: boolean
  origin?: string
  omitOriginValidation?: boolean
}) {
  const { request, wallet, jar, origin, omitOriginValidation } = options

  if (isOpenid4vpAuthorizationRequestDcApi(request)) {
    const parsed = parseWithErrorHandling(
      zOpenid4vpAuthorizationRequestDcApi,
      request,
      'Invalid authorization request. Could not parse openid4vp dc_api authorization request.'
    )

    validateOpenid4vpAuthorizationRequestDcApiPayload({
      params: parsed,
      isJarRequest: jar,
      omitOriginValidation,
      origin,
    })

    return parsed
  }

  const authRequestPayload = parseWithErrorHandling(
    zOpenid4vpAuthorizationRequest,
    request,
    'Invalid authorization request. Could not parse openid4vp authorization request.'
  )
  validateOpenid4vpAuthorizationRequestPayload({ params: authRequestPayload, walletVerificationOptions: wallet })

  return authRequestPayload
}
