import type { PexPresentationSubmission } from '../models/z-pex'
import type { VpTokenPresentationEntry } from '../vp-token/z-vp-token'

export interface ValidateOpenid4VpPexAuthorizationResponseResult {
  type: 'pex'

  pex: {
    presentationSubmission: PexPresentationSubmission
    presentations: [VpTokenPresentationEntry, ...VpTokenPresentationEntry[]]
  } & (
    | { scope: string; presentationDefinition?: never }
    | { scope?: never; presentationDefinition: Record<string, unknown> | string }
  )
}

export interface ValidateOpenid4VpDcqlAuthorizationResponseResult {
  type: 'dcql'
  dcql: {
    presentations: Record<string, [VpTokenPresentationEntry, ...VpTokenPresentationEntry[]]>
  } & ({ scope: string; query?: never } | { scope?: never; query: unknown })
}

export type ValidateOpenid4VpAuthorizationResponseResult =
  | ValidateOpenid4VpPexAuthorizationResponseResult
  | ValidateOpenid4VpDcqlAuthorizationResponseResult
