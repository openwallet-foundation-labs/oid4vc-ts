import { Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import type { Openid4vpAuthorizationRequest } from './authorization-request/z-authorization-request'
import {
  type Openid4vpAuthorizationRequestDcApi,
  isOpenid4vpAuthorizationRequestDcApi,
} from './authorization-request/z-authorization-request-dc-api'
import { zClientIdScheme } from './client-identifier-scheme/z-client-id-scheme'

export const Openid4vpVersion = [18, 19, 20, 21, 22, 23, 24] as const
export type OpenId4VpVersion = (typeof Openid4vpVersion)[number]

export function parseAuthorizationRequestVersion(
  request: Openid4vpAuthorizationRequest | Openid4vpAuthorizationRequestDcApi
): OpenId4VpVersion {
  const requirements: ['<' | '>=', OpenId4VpVersion][] = []

  if (
    isOpenid4vpAuthorizationRequestDcApi(request) &&
    (request.response_mode === 'w3c_dc_api' || request.response_mode === 'w3c_dc_api.jwt')
  ) {
    requirements.push(['<', 23])
    requirements.push(['>=', 21])
  }

  if (
    (isOpenid4vpAuthorizationRequestDcApi(request) && request.response_mode === 'dc_api') ||
    request.response_mode === 'dc_api.jwt'
  ) {
    requirements.push(['>=', 23])
  }

  if (isOpenid4vpAuthorizationRequestDcApi(request) && (request.transaction_data || request.dcql_query)) {
    requirements.push(['>=', 23])
  }

  // 22

  if (request.dcql_query) {
    requirements.push(['>=', 22])
  }

  if (request.transaction_data) {
    requirements.push(['>=', 22])
  }

  if (request.client_id_scheme) {
    requirements.push(['<', 22])
  }

  // what happens if we don't have a client_id_scheme?

  // if the client_id is prefixed with a scheme, we know for sure that the version is >= 22
  // if it is not prefixed we don't know anything since it can default in all versions to pre-registered
  if (request.client_id) {
    const colonIndex = request.client_id.indexOf(':')
    const schemePart = request.client_id.substring(0, colonIndex)
    const parsedScheme = zClientIdScheme.safeParse(schemePart)

    // we know this for sure
    if (parsedScheme.success && parsedScheme.data !== 'did' && parsedScheme.data !== 'https') {
      requirements.push(['>=', 22])
    }
  }

  // only possible with dc_api which is available in 21
  if (!request.client_id) {
    requirements.push(['>=', 21])
  }

  // 21

  if ('client_metadata_uri' in request) {
    requirements.push(['<', 21])
  }

  if (isOpenid4vpAuthorizationRequestDcApi(request)) {
    requirements.push(['>=', 21])
  }

  if ('request_uri_method' in request || 'wallet_nonce' in request) {
    requirements.push(['>=', 21])
  }

  // 20

  if (request.client_id_scheme === 'verifier_attestation') {
    requirements.push(['>=', 20])
  }

  // 19

  if (request.client_id_scheme === 'x509_san_dns' || request.client_id_scheme === 'x509_san_uri') {
    requirements.push(['>=', 19])
  }

  // The minimum version which satisfies all requirements
  const lessThanVersions = requirements.filter(([operator]) => operator === '<').map(([_, version]) => version)

  const greaterThanVersions = requirements.filter(([operator]) => operator === '>=').map(([_, version]) => version)

  // Find the minimum version that satisfies all "less than" constraints
  const highestPossibleVersion =
    lessThanVersions.length > 0 ? (Math.max(Math.min(...lessThanVersions) - 1, 18) as OpenId4VpVersion) : (24 as const) // Default to highest version

  // Find the maximum version that satisfies all "greater than or equal to" constraints
  const lowestRequiredVersion =
    greaterThanVersions.length > 0 ? (Math.max(...greaterThanVersions) as OpenId4VpVersion) : (18 as const) // Default to lowest version

  // The acceptable range is [lowestRequiredVersion, highestPossibleVersion]
  // We return the lowest possible version that satisfies all constraints
  if (lowestRequiredVersion > highestPossibleVersion) {
    // No valid version exists that satisfies all constraints
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: 'Could not infer openid4vp version from the openid4vp request payload.',
    })
  }

  return highestPossibleVersion
}
