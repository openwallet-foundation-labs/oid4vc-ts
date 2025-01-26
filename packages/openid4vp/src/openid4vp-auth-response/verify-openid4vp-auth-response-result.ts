import type { VpTokenPresentationParseResult } from '../vp-token/parse-presentations-from-vp-token'

export interface VerifyOpenid4VpPexAuthorizationResponseResult {
  type: 'pex'
  pex: {
    presentationSubmission: unknown
    presentations: [VpTokenPresentationParseResult, ...VpTokenPresentationParseResult[]]
  } & (
    | { scope: string; presentationDefinition?: never }
    | { scope?: never; presentationDefinition: Record<string, unknown> | string }
  )
}

export interface VerifyOpenid4VpDcqlAuthorizationResponseResult {
  type: 'dcql'
  dcql: {
    presentation: VpTokenPresentationParseResult
  } & ({ scope: string; query?: never } | { scope?: never; query: unknown })
}

export type VerifyOpenid4VpAuthorizationResponseResult =
  | VerifyOpenid4VpPexAuthorizationResponseResult
  | VerifyOpenid4VpDcqlAuthorizationResponseResult
