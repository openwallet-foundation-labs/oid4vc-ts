import type { VpTokenPresentationParseResult } from '../vp-token/parse-presentations-from-vp-token'

export interface ValidateOpenid4VpPexAuthorizationResponseResult {
  type: 'pex'
  pex: {
    presentationSubmission: unknown
    presentations: [VpTokenPresentationParseResult, ...VpTokenPresentationParseResult[]]
  } & (
    | { scope: string; presentationDefinition?: never }
    | { scope?: never; presentationDefinition: Record<string, unknown> | string }
  )
}

export interface ValidateOpenid4VpDcqlAuthorizationResponseResult {
  type: 'dcql'
  dcql: {
    presentation: Record<string, VpTokenPresentationParseResult>
  } & ({ scope: string; query?: never } | { scope?: never; query: unknown })
}

export type ValidateOpenid4VpAuthorizationResponseResult =
  | ValidateOpenid4VpPexAuthorizationResponseResult
  | ValidateOpenid4VpDcqlAuthorizationResponseResult
