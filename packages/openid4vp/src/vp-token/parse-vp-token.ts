import { parseIfJson, parseWithErrorHandling } from '@openid4vc/utils'
import { type VpTokenDcql, type VpTokenPexEntry, zVpTokenDcql, zVpTokenPex } from './z-vp-token'

export function parsePexVpToken(vpToken: unknown): [VpTokenPexEntry, ...VpTokenPexEntry[]] {
  const parsedVpToken = parseWithErrorHandling(
    zVpTokenPex,
    parseIfJson(vpToken),
    'Could not parse presentation exchange vp_token. Expected a string or an array of strings'
  )

  return Array.isArray(parsedVpToken) ? (parsedVpToken as [VpTokenPexEntry, ...VpTokenPexEntry[]]) : [parsedVpToken]
}

export function parseDcqlVpToken(vpToken: unknown): VpTokenDcql {
  return parseWithErrorHandling(
    zVpTokenDcql,
    parseIfJson(vpToken),
    'Could not parse dcql vp_token. Expected an object where the values are encoded presentations'
  )
}
