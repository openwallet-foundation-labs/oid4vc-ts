import { Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import type { Openid4vpAuthorizationRequest } from './authorization-request/z-authorization-request'
import {
  type Openid4vpAuthorizationRequestDcApi,
  isOpenid4vpAuthorizationRequestDcApi,
} from './authorization-request/z-authorization-request-dc-api'
import { zClientIdPrefix } from './client-identifier-prefix/z-client-id-prefix'

export const Openid4vpVersion = [18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29] as const
export type OpenId4VpVersion = (typeof Openid4vpVersion)[number]

export function parseAuthorizationRequestVersion(
  request: Openid4vpAuthorizationRequest | Openid4vpAuthorizationRequestDcApi
): OpenId4VpVersion {
  const requirements: ['<' | '>=', OpenId4VpVersion][] = []

  // 26
  if (
    request.client_id?.startsWith('openid_federation:') ||
    request.client_id?.startsWith('decentralized_identifier:')
  ) {
    requirements.push(['>=', 26])
  }

  if (request.client_id?.startsWith('did:')) {
    requirements.push(['<', 26])
  }

  if (request.presentation_definition || request.presentation_definition_uri) {
    requirements.push(['>=', 26])
  }

  if (request.verifier_attestations) {
    requirements.push(['>=', 26])
  }

  // 25

  if (request.client_id?.startsWith('x509_san_uri:')) {
    requirements.push(['<', 25])
  }

  if (request.client_id?.startsWith('x509_hash:')) {
    requirements.push(['>=', 25])
  }

  // 23
  if (
    isOpenid4vpAuthorizationRequestDcApi(request) &&
    (request.response_mode === 'w3c_dc_api' || request.response_mode === 'w3c_dc_api.jwt')
  ) {
    requirements.push(['<', 23])
    requirements.push(['>=', 21])
  }

  if (
    isOpenid4vpAuthorizationRequestDcApi(request) &&
    (request.response_mode === 'dc_api' || request.response_mode === 'dc_api.jwt')
  ) {
    requirements.push(['>=', 23])
  }

  if (isOpenid4vpAuthorizationRequestDcApi(request) && (request.transaction_data || request.dcql_query)) {
    requirements.push(['>=', 23])
  }

  // 22

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
    const parsedScheme = zClientIdPrefix.safeParse(schemePart)

    // we know this for sure
    if (parsedScheme.success && parsedScheme.data !== 'did' && parsedScheme.data !== 'https') {
      requirements.push(['>=', 22])
    }
  }

  // 21

  // only possible with dc_api which is available in 21
  if (!request.client_id) {
    requirements.push(['>=', 21])
  }

  // NOTE: DCQL was added in 22, but we've used it with draft 21 before, so it's
  // not 100% correct, but prevents interop issues
  if (request.dcql_query) {
    requirements.push(['>=', 21])
  }

  if (request.client_metadata_uri) {
    requirements.push(['<', 21])
  }

  if (isOpenid4vpAuthorizationRequestDcApi(request)) {
    requirements.push(['>=', 21])
  }

  if (request.request_uri_method || request.wallet_nonce) {
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
