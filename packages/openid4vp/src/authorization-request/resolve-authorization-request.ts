import { type CallbackContext, Oauth2Error } from '@openid4vc/oauth2'
import { parseWithErrorHandling } from '@openid4vc/utils'
import z from 'zod'
import { parseClientIdentifier } from '../client-identifier-scheme/parse-client-identifier-scheme'
import { verifyJarRequest } from '../jar/handle-jar-request/verify-jar-request'
import { type JarAuthRequest, isJarAuthRequest, zJarAuthRequest } from '../jar/z-jar-auth-request'
import { parseTransactionData } from '../transaction-data/parse-transaction-data'
import {
  type WalletVerificationOptions,
  validateOpenid4vpAuthorizationRequestPayload,
} from './validate-authorization-request'
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
  callbacks: Pick<CallbackContext, 'verifyJwt' | 'decryptJwe' | 'getX509CertificateMetadata'>
}

export async function resolveOpenid4vpAuthorizationRequest(options: ResolveOpenid4vpAuthorizationRequestOptions) {
  const { request, wallet, callbacks, origin } = options

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
    })
  } else {
    authRequestPayload = parseOpenid4vpAuthorizationRequestPayload({ request, wallet, jar: false, origin })
  }

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

function parseOpenid4vpAuthorizationRequestPayload(options: {
  request: Record<string, unknown>
  wallet?: WalletVerificationOptions
  jar: boolean
  origin?: string
}) {
  const { request, wallet, jar, origin } = options

  if (isOpenid4vpAuthorizationRequestDcApi(request)) {
    const parsed = parseWithErrorHandling(
      zOpenid4vpAuthorizationRequestDcApi,
      request,
      'Invalid authorization request. Could not parse openid4vp dc_api authorization request.'
    )

    if (jar && !request.expected_origins) {
      throw new Oauth2Error(
        `The 'expected_origins' parameter MUST be present when using the dc_api response mode in combinaction with jar.`
      )
    }

    if (request.expected_origins) {
      if (!origin) {
        throw new Oauth2Error(
          `The 'origin' validation parameter MUST be present when resolving an openid4vp dc_api authorization request.`
        )
      }

      if (request.expected_origins && !request.expected_origins.includes(origin)) {
        throw new Oauth2Error(
          `The 'expected_origins' parameter MUST include the origin of the authorization request. Current: ${request.expected_origins}`
        )
      }
    }

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
