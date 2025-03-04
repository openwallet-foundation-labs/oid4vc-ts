import type { PexPresentationSubmission } from '../models/z-pex'
import type { VpTokenDcql, VpTokenPexEntry } from '../vp-token/z-vp-token'

export interface ValidateOpenid4VpPexAuthorizationResponseResult {
  type: 'pex'

  pex: {
    presentationSubmission: PexPresentationSubmission
    presentations: [VpTokenPexEntry, ...VpTokenPexEntry[]]
  } & (
    | { scope: string; presentationDefinition?: never }
    | { scope?: never; presentationDefinition: Record<string, unknown> | string }
  )
}

export interface ValidateOpenid4VpDcqlAuthorizationResponseResult {
  type: 'dcql'
  dcql: {
    presentations: VpTokenDcql
  } & ({ scope: string; query?: never } | { scope?: never; query: unknown })
}

export type ValidateOpenid4VpAuthorizationResponseResult =
  | ValidateOpenid4VpPexAuthorizationResponseResult
  | ValidateOpenid4VpDcqlAuthorizationResponseResult
