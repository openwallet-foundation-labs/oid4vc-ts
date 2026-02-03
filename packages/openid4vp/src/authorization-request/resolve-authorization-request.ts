import { type CallbackContext, Oauth2Error, Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { parseWithErrorHandling } from '@openid4vc/utils'
import z from 'zod'
import {
  type ParsedClientIdentifier,
  validateOpenid4vpClientId,
} from '../client-identifier-prefix/parse-client-identifier-prefix'
import { fetchClientMetadata } from '../fetch-client-metadata'
import { type VerifiedJarRequest, verifyJarRequest } from '../jar/handle-jar-request/verify-jar-request'
import {
  isJarAuthorizationRequest,
  type Openid4vpJarAuthorizationRequest,
  zOpenid4vpJarAuthorizationRequest,
} from '../jar/z-jar-authorization-request'
import type { PexPresentationDefinition } from '../models/z-pex'
import { type ParsedTransactionDataEntry, parseTransactionData } from '../transaction-data/parse-transaction-data'
import { type Openid4vpVersionNumber, parseAuthorizationRequestVersion } from '../version'
import {
  validateOpenid4vpAuthorizationRequestPayload,
  type WalletVerificationOptions,
} from './validate-authorization-request'
import { validateOpenid4vpAuthorizationRequestDcApiPayload } from './validate-authorization-request-dc-api'
import { validateOpenid4vpAuthorizationRequestIaePayload } from './validate-authorization-request-iae'
import { type Openid4vpAuthorizationRequest, zOpenid4vpAuthorizationRequest } from './z-authorization-request'
import {
  isOpenid4vpAuthorizationRequestDcApi,
  type Openid4vpAuthorizationRequestDcApi,
  zOpenid4vpAuthorizationRequestDcApi,
} from './z-authorization-request-dc-api'
import {
  isOpenid4vpAuthorizationRequestIae,
  type Openid4vpAuthorizationRequestIae,
  zOpenid4vpAuthorizationRequestIae,
} from './z-authorization-request-iae'

export interface ResolveOpenid4vpAuthorizationRequestOptions {
  authorizationRequestPayload:
    | Openid4vpAuthorizationRequest
    | Openid4vpAuthorizationRequestDcApi
    | Openid4vpAuthorizationRequestIae
    | Openid4vpJarAuthorizationRequest
  wallet?: WalletVerificationOptions

  /**
   * The response mode that is expected for the resolved presentation request.
   */
  responseMode: ExpectedResponseMode

  callbacks: Pick<CallbackContext, 'verifyJwt' | 'decryptJwe' | 'getX509CertificateMetadata' | 'fetch' | 'hash'>
}

export type ResolvedOpenid4vpAuthorizationRequest = {
  transactionData?: ParsedTransactionDataEntry[]
  authorizationRequestPayload:
    | Openid4vpAuthorizationRequest
    | Openid4vpAuthorizationRequestDcApi
    | Openid4vpAuthorizationRequestIae
  jar: VerifiedJarRequest | undefined
  client: ParsedClientIdentifier
  pex?: {
    presentation_definition?: PexPresentationDefinition
    presentation_definition_uri?: string
  }
  dcql?: { query: unknown } | undefined

  /**
   * The highest possible version number based on (draft)-version checks done on the request.
   *
   * 100 means 1.0 final, all other numbers are draft versions.
   */
  version: Openid4vpVersionNumber
}

export async function resolveOpenid4vpAuthorizationRequest(
  options: ResolveOpenid4vpAuthorizationRequestOptions
): Promise<ResolvedOpenid4vpAuthorizationRequest> {
  const { wallet, callbacks } = options

  let authorizationRequestPayload:
    | Openid4vpAuthorizationRequest
    | ((Openid4vpAuthorizationRequestDcApi | Openid4vpAuthorizationRequestIae) & {
        presentation_definition_uri?: never
      })

  const parsed = parseWithErrorHandling(
    z.union([
      zOpenid4vpAuthorizationRequestDcApi,
      zOpenid4vpAuthorizationRequestIae,
      zOpenid4vpAuthorizationRequest,
      zOpenid4vpJarAuthorizationRequest,
    ]),
    options.authorizationRequestPayload,
    'Invalid authorization request. Could not parse openid4vp authorization request as openid4vp or jar auth request.'
  )

  let jar: VerifiedJarRequest | undefined
  if (isJarAuthorizationRequest(parsed)) {
    jar = await verifyJarRequest({
      jarRequestParams: parsed,
      callbacks,
      wallet,
      // For IAE/DC API only request is allowed
      allowRequestUri: options.responseMode.type === 'direct_post',
    })

    const parsedJarAuthorizationRequestPayload = parseWithErrorHandling(
      z.union([zOpenid4vpAuthorizationRequestDcApi, zOpenid4vpAuthorizationRequestIae, zOpenid4vpAuthorizationRequest]),
      jar.authorizationRequestPayload,
      'Invalid authorization request. Could not parse jar request payload as openid4vp auth request.'
    )

    authorizationRequestPayload = validateOpenId4vpAuthorizationRequestPayload({
      authorizationRequestPayload: parsedJarAuthorizationRequestPayload,
      wallet,
      jar: true,
      responseMode: options.responseMode,
    })
  } else {
    authorizationRequestPayload = validateOpenId4vpAuthorizationRequestPayload({
      authorizationRequestPayload: parsed,
      wallet,
      jar: false,

      responseMode: options.responseMode,
    })
  }

  const version = parseAuthorizationRequestVersion(authorizationRequestPayload)
  let clientMetadata = authorizationRequestPayload.client_metadata
  if (
    !isOpenid4vpAuthorizationRequestDcApi(authorizationRequestPayload) &&
    !isOpenid4vpAuthorizationRequestIae(authorizationRequestPayload) &&
    !clientMetadata &&
    authorizationRequestPayload.client_metadata_uri
  ) {
    clientMetadata = await fetchClientMetadata({ clientMetadataUri: authorizationRequestPayload.client_metadata_uri })
  }

  const clientMeta = await validateOpenid4vpClientId({
    authorizationRequestPayload: {
      ...authorizationRequestPayload,
      client_metadata: clientMetadata,
    },
    jar,

    callbacks,
    origin: options.responseMode.type === 'dc_api' ? options.responseMode.expectedOrigin : undefined,
    version,
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
    version,
  }
}

type ExpectedResponseMode =
  | {
      /**
       * Enforces the response is `iae` or `iae_post`, meaning the presentation
       * is created as part of an issuance session.
       */
      type: 'iae'

      /**
       * The expectedUrl for the IAE session. Must always be provided, but will
       * only be verified if the OpenID4VP request is signed (and thus MUST contain `expected_url`)
       */
      expectedUrl: string
    }
  | {
      /**
       * Enforces the response is `dc_api` or `dc_api.jwt` (including legacy support for `w3c_dc_api` and `w3c_dc_api.jwt`),
       * meaning the presentation will be shared using the Digital Credentials API.
       */
      type: 'dc_api'

      /**
       * The expected origin for the DC API session. Must always be provided, but will
       * only be verified if the OpenID4VP request is signed (and thus MUST contain `expected_origins`)
       */
      expectedOrigin: string
    }
  | {
      /**
       * Enforces the response is `direct_post` or `direct_post.jwt`
       */
      type: 'direct_post'
    }

function validateOpenId4vpAuthorizationRequestPayload(options: {
  authorizationRequestPayload:
    | Openid4vpAuthorizationRequest
    | Openid4vpAuthorizationRequestDcApi
    | Openid4vpAuthorizationRequestIae
  wallet?: WalletVerificationOptions
  jar: boolean

  responseMode: ExpectedResponseMode
}) {
  const { authorizationRequestPayload, wallet, jar, responseMode } = options

  if (isOpenid4vpAuthorizationRequestDcApi(authorizationRequestPayload)) {
    if (responseMode.type !== 'dc_api') {
      throw new Oauth2Error(
        `Authorization request uses response mode ${authorizationRequestPayload.response_mode}, but expected to use a response mode in the ${responseMode.type} category.`
      )
    }

    validateOpenid4vpAuthorizationRequestDcApiPayload({
      params: authorizationRequestPayload,
      isJarRequest: jar,
      origin: responseMode.expectedOrigin,
    })

    return authorizationRequestPayload
  }

  if (isOpenid4vpAuthorizationRequestIae(authorizationRequestPayload)) {
    if (responseMode.type !== 'iae') {
      throw new Oauth2Error(
        `Authorization request uses response mode ${authorizationRequestPayload.response_mode}, but expected to use a response mode in the ${responseMode.type} category.`
      )
    }

    validateOpenid4vpAuthorizationRequestIaePayload({
      params: authorizationRequestPayload,
      isJarRequest: jar,
      expectedUrl: responseMode.expectedUrl,
    })

    return authorizationRequestPayload
  }

  if (responseMode.type !== 'direct_post') {
    throw new Oauth2Error(
      `Authorization request uses response mode ${authorizationRequestPayload.response_mode}, but expected to use a response mode in the ${responseMode.type} category.`
    )
  }

  validateOpenid4vpAuthorizationRequestPayload({
    params: authorizationRequestPayload,
    walletVerificationOptions: wallet,
  })
  return authorizationRequestPayload
}
