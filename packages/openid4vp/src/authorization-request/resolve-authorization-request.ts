import { type CallbackContext, Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { parseWithErrorHandling } from '@openid4vc/utils'
import z from 'zod'
import {
  type ParsedClientIdentifier,
  parseClientIdentifier,
} from '../client-identifier-scheme/parse-client-identifier-scheme'
import { fetchClientMetadata } from '../fetch-client-metadata'
import { type VerifiedJarRequest, verifyJarRequest } from '../jar/handle-jar-request/verify-jar-request'
import { type JarAuthRequest, isJarAuthRequest, zJarAuthRequest } from '../jar/z-jar-auth-request'
import type { WalletMetadata } from '../models/z-wallet-metadata'
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
  requestPayload: Openid4vpAuthorizationRequest | JarAuthRequest
  wallet?: WalletVerificationOptions
  origin?: string
  omitOriginValidation?: boolean
  callbacks: Pick<CallbackContext, 'verifyJwt' | 'decryptJwe' | 'getX509CertificateMetadata'>
}

export type ResolvedOpenid4vpAuthRequest = {
  transactionData?: TransactionData
  requestPayload: Openid4vpAuthorizationRequest | Openid4vpAuthorizationRequestDcApi
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
  const { requestPayload, wallet, callbacks, origin, omitOriginValidation } = options

  let authRequestPayload:
    | Openid4vpAuthorizationRequest
    | (Openid4vpAuthorizationRequestDcApi & { presentation_definition_uri?: never })

  const parsed = parseWithErrorHandling(
    z.union([zOpenid4vpAuthorizationRequestDcApi, zOpenid4vpAuthorizationRequest, zJarAuthRequest]),
    requestPayload,
    'Invalid authorization request. Could not parse openid4vp authorization request as openid4vp or jar auth request.'
  )

  let jar: VerifiedJarRequest | undefined
  if (isJarAuthRequest(parsed)) {
    jar = await verifyJarRequest({ jarRequestParams: parsed, callbacks, wallet })

    const parsedJarAuthRequestPayload = parseWithErrorHandling(
      z.union([zOpenid4vpAuthorizationRequestDcApi, zOpenid4vpAuthorizationRequest]),
      jar.authRequestParams,
      'Invalid authorization request. Could not parse jar request payload as openid4vp auth request.'
    )

    authRequestPayload = validateOpenId4vpPayload({
      requestPayload: parsedJarAuthRequestPayload,
      wallet,
      jar: true,
      origin,
      omitOriginValidation,
    })
  } else {
    authRequestPayload = validateOpenId4vpPayload({
      requestPayload: parsed,
      wallet,
      jar: false,
      origin,
      omitOriginValidation,
    })
  }

  let clientMetadata: WalletMetadata | undefined
  if (!isOpenid4vpAuthorizationRequestDcApi(authRequestPayload) && authRequestPayload.client_metadata_uri) {
    clientMetadata = await fetchClientMetadata({ clientMetadataUri: authRequestPayload.client_metadata_uri })
  }

  const clientMeta = parseClientIdentifier({
    request: { ...authRequestPayload, client_metadata: clientMetadata ?? authRequestPayload.client_metadata },
    jar,
    callbacks,
    origin,
  })

  let pex: ResolvedOpenid4vpAuthRequest['pex'] | undefined
  let dcql: ResolvedOpenid4vpAuthRequest['dcql'] | undefined

  if (authRequestPayload.presentation_definition || authRequestPayload.presentation_definition_uri) {
    if (authRequestPayload.presentation_definition_uri) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: 'Cannot fetch presentation definition from URI. Not supported.',
      })
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
    requestPayload: authRequestPayload,
    jar,
    client: { ...clientMeta },
    pex,
    dcql,
  }
}

function validateOpenId4vpPayload(options: {
  requestPayload: Openid4vpAuthorizationRequest | Openid4vpAuthorizationRequestDcApi
  wallet?: WalletVerificationOptions
  jar: boolean
  origin?: string
  omitOriginValidation?: boolean
}) {
  const { requestPayload, wallet, jar, origin, omitOriginValidation } = options

  if (isOpenid4vpAuthorizationRequestDcApi(requestPayload)) {
    validateOpenid4vpAuthorizationRequestDcApiPayload({
      params: requestPayload,
      isJarRequest: jar,
      omitOriginValidation,
      origin,
    })

    return requestPayload
  }

  validateOpenid4vpAuthorizationRequestPayload({ params: requestPayload, walletVerificationOptions: wallet })
  return requestPayload
}
