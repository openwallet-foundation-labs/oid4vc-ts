import { parseIfJson, parseWithErrorHandling } from '@openid4vc/utils'
import { type VpTokenPresentationEntry, zVpTokenDcql, zVpTokenPex } from './z-vp-token'

export function parsePexVpToken(vpToken: unknown): [VpTokenPresentationEntry, ...VpTokenPresentationEntry[]] {
  const parsedVpToken = parseWithErrorHandling(
    zVpTokenPex,
    parseIfJson(vpToken),
    'Could not parse presentation exchange vp_token. Expected a string or an array of strings'
  )

  return Array.isArray(parsedVpToken)
    ? (parsedVpToken as [VpTokenPresentationEntry, ...VpTokenPresentationEntry[]])
    : [parsedVpToken]
}

export function parseDcqlVpToken(
  vpToken: unknown
): Record<string, [VpTokenPresentationEntry, ...VpTokenPresentationEntry[]]> {
  const parsedVpToken = parseWithErrorHandling(
    zVpTokenDcql,
    parseIfJson(vpToken),
    'Could not parse dcql vp_token. Expected an object where the values are encoded presentations'
  )

  return Object.fromEntries(
    Object.entries(parsedVpToken).map(([queryId, presentations]) => [
      queryId,
      Array.isArray(presentations)
        ? (presentations as [VpTokenPresentationEntry, ...VpTokenPresentationEntry[]])
        : [presentations],
    ])
  )
}
