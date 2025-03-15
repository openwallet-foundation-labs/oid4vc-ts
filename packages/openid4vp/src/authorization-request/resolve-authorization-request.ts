import { type CallbackContext, Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { parseWithErrorHandling } from '@openid4vc/utils'
import z from 'zod'
import {
  type ParsedClientIdentifier,
  parseClientIdentifier,
} from '../client-identifier-scheme/parse-client-identifier-scheme'
import { fetchClientMetadata } from '../fetch-client-metadata'
import { type VerifiedJarRequest, verifyJarRequest } from '../jar/handle-jar-request/verify-jar-request'
import {
  type JarAuthorizationRequest,
  isJarAuthorizationRequest,
  zJarAuthorizationRequest,
} from '../jar/z-jar-authorization-request'
import type { PexPresentationDefinition } from '../models/z-pex'
import { type ParsedTransactionDataEntry, parseTransactionData } from '../transaction-data/parse-transaction-data'
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
  authorizationRequestPayload: Openid4vpAuthorizationRequest | JarAuthorizationRequest
  wallet?: WalletVerificationOptions
  origin?: string
  disableOriginValidation?: boolean
  callbacks: Pick<CallbackContext, 'verifyJwt' | 'decryptJwe' | 'getX509CertificateMetadata'>
}

export type ResolvedOpenid4vpAuthorizationRequest = {
  transactionData?: ParsedTransactionDataEntry[]
  authorizationRequestPayload: Openid4vpAuthorizationRequest | Openid4vpAuthorizationRequestDcApi
  jar: VerifiedJarRequest | undefined
  client: ParsedClientIdentifier
  pex?: {
    presentation_definition?: PexPresentationDefinition
    presentation_definition_uri?: string
  }
  dcql?: { query: unknown } | undefined
}
export async function resolveOpenid4vpAuthorizationRequest(
  options: ResolveOpenid4vpAuthorizationRequestOptions
): Promise<ResolvedOpenid4vpAuthorizationRequest> {
  const { wallet, callbacks, origin, disableOriginValidation } = options

  let authorizationRequestPayload:
    | Openid4vpAuthorizationRequest
    | (Openid4vpAuthorizationRequestDcApi & { presentation_definition_uri?: never })

  const parsed = parseWithErrorHandling(
    z.union([zOpenid4vpAuthorizationRequestDcApi, zOpenid4vpAuthorizationRequest, zJarAuthorizationRequest]),
    options.authorizationRequestPayload,
    'Invalid authorization request. Could not parse openid4vp authorization request as openid4vp or jar auth request.'
  )

  let jar: VerifiedJarRequest | undefined
  if (isJarAuthorizationRequest(parsed)) {
    jar = await verifyJarRequest({ jarRequestParams: parsed, callbacks, wallet })

    const parsedJarAuthorizationRequestPayload = parseWithErrorHandling(
      z.union([zOpenid4vpAuthorizationRequestDcApi, zOpenid4vpAuthorizationRequest]),
      jar.authorizationRequestParams,
      'Invalid authorization request. Could not parse jar request payload as openid4vp auth request.'
    )

    authorizationRequestPayload = validateOpenId4vpAuthorizationRequestPayload({
      authorizationRequestPayload: parsedJarAuthorizationRequestPayload,
      wallet,
      jar: true,
      origin,
      disableOriginValidation,
    })
  } else {
    authorizationRequestPayload = validateOpenId4vpAuthorizationRequestPayload({
      authorizationRequestPayload: parsed,
      wallet,
      jar: false,
      origin,
      disableOriginValidation,
    })
  }

  let clientMetadata = authorizationRequestPayload.client_metadata
  if (
    !isOpenid4vpAuthorizationRequestDcApi(authorizationRequestPayload) &&
    !clientMetadata &&
    authorizationRequestPayload.client_metadata_uri
  ) {
    clientMetadata = await fetchClientMetadata({ clientMetadataUri: authorizationRequestPayload.client_metadata_uri })
  }

  const clientMeta = parseClientIdentifier({
    authorizationRequestPayload: {
      ...authorizationRequestPayload,
      client_metadata: clientMetadata,
    },
    jar,
    callbacks,
    origin,
  })

  let pex: ResolvedOpenid4vpAuthorizationRequest['pex'] | undefined
  let dcql: ResolvedOpenid4vpAuthorizationRequest['dcql'] | undefined

  if (authorizationRequestPayload.presentation_definition || authorizationRequestPayload.presentation_definition_uri) {
    if (authorizationRequestPayload.presentation_definition_uri) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: 'Cannot fetch presentation definition from URI. Not supported.',
      })
    }

    pex = {
      presentation_definition: authorizationRequestPayload.presentation_definition,
      presentation_definition_uri: authorizationRequestPayload.presentation_definition_uri,
    }
  }

  if (authorizationRequestPayload.dcql_query) {
    dcql = { query: authorizationRequestPayload.dcql_query }
  }

  const transactionData = authorizationRequestPayload.transaction_data
    ? parseTransactionData({ transactionData: authorizationRequestPayload.transaction_data })
    : undefined

  return {
    transactionData,
    authorizationRequestPayload,
    jar,
    client: clientMeta,
    pex,
    dcql,
  }
}

function validateOpenId4vpAuthorizationRequestPayload(options: {
  authorizationRequestPayload: Openid4vpAuthorizationRequest | Openid4vpAuthorizationRequestDcApi
  wallet?: WalletVerificationOptions
  jar: boolean
  origin?: string
  disableOriginValidation?: boolean
}) {
  const { authorizationRequestPayload, wallet, jar, origin, disableOriginValidation } = options

  if (isOpenid4vpAuthorizationRequestDcApi(authorizationRequestPayload)) {
    validateOpenid4vpAuthorizationRequestDcApiPayload({
      params: authorizationRequestPayload,
      isJarRequest: jar,
      disableOriginValidation,
      origin,
    })

    return authorizationRequestPayload
  }

  validateOpenid4vpAuthorizationRequestPayload({
    params: authorizationRequestPayload,
    walletVerificationOptions: wallet,
  })
  return authorizationRequestPayload
}
