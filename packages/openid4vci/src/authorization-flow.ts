import type { CreateAuthorizationRequestUrlOptions, CreatePkceReturn, RequestDpopOptions } from '@openid4vc/oauth2'
import type { CredentialOfferObject } from './credential-offer/z-credential-offer'
import type { IssuerMetadataResult } from './metadata/fetch-issuer-metadata'

export interface InitiateAuthorizationOptions
  extends Omit<CreateAuthorizationRequestUrlOptions, 'callbacks' | 'authorizationServerMetadata'> {
  credentialOffer: CredentialOfferObject
  issuerMetadata: IssuerMetadataResult
}

export enum AuthorizationFlow {
  Oauth2Redirect = 'Oauth2Redirect',
  PresentationDuringIssuance = 'PresentationDuringIssuance',
  InteractiveAuthorizationOpenid4vp = 'InteractiveAuthorizationOpenid4vp',
}

/**
 * Legacy presentation during issuance flow based on design from
 * SPRIN-D. Not recommended for new implementations.
 */
export interface AuthorizationFlowPresentationDuringIssuance {
  authorizationFlow: AuthorizationFlow.PresentationDuringIssuance
  authorizationServer: string
  dpop?: RequestDpopOptions

  openid4vpRequestUrl: string
  authSession: string
}

/**
 * Interactive authorization using OpenID4VP as defined in OpenID4VCI
 */
export interface AuthorizationFlowInteractiveAuthorizationOpenid4vp {
  authorizationFlow: AuthorizationFlow.InteractiveAuthorizationOpenid4vp
  authorizationServer: string
  dpop?: RequestDpopOptions

  openid4vpRequest: Record<string, unknown>
  authSession: string
}

/**
 * Regular authorization based on web redirect
 */
export interface AuthorizationFlowOauth2Redirect {
  authorizationFlow: AuthorizationFlow.Oauth2Redirect
  authorizationServer: string
  dpop?: RequestDpopOptions
  pkce?: CreatePkceReturn

  authorizationRequestUrl: string
}

export type AuthorizationFlowReturn =
  | AuthorizationFlowPresentationDuringIssuance
  | AuthorizationFlowInteractiveAuthorizationOpenid4vp
  | AuthorizationFlowOauth2Redirect
