import { Oauth2Error, decodeJwt } from '@openid4vc/oauth2'
import { vCompactJwt } from '@openid4vc/oauth2'
import { parseIfJson } from '@openid4vc/utils'
import * as v from 'valibot'
import type { VpToken } from './v-vp-token'

export type VpTokenPresentationParseResult =
  | {
      format: 'dc+sd-jwt' | 'mso_mdoc' | 'jwt_vp_json'
      presentation: string
      path: string
      nonce?: string
    }
  | {
      format: 'ldp_vp' | 'ac_vp'
      presentation: Record<string, unknown>
      path: string
      nonce?: string
    }

export function parsePresentationsFromVpToken(options: { vpToken: VpToken }): [
  VpTokenPresentationParseResult,
  ...VpTokenPresentationParseResult[],
] {
  const { vpToken: _vpToken } = options
  const vpToken = parseIfJson(_vpToken)

  if (Array.isArray(vpToken)) {
    if (vpToken.length === 0) {
      throw new Oauth2Error('Could not parse vp_token. vp_token is an empty array.')
    }

    return vpToken.map((token, idx) => parseSinglePresentationsFromVpToken({ vpToken: token, path: `$[${idx}]` })) as [
      VpTokenPresentationParseResult,
      ...VpTokenPresentationParseResult[],
    ]
  }

  if (typeof vpToken === 'string' || typeof vpToken === 'object') {
    return [parseSinglePresentationsFromVpToken({ vpToken, path: '$' })]
  }

  throw new Oauth2Error(
    `Could not parse vp_token. Expected a string or an array of strings. Received: ${typeof vpToken}`
  )
}

export function parseSinglePresentationsFromVpToken(options: {
  vpToken: unknown
  path: string
}): VpTokenPresentationParseResult {
  const { vpToken: _vpToken } = options

  const vpToken = parseIfJson(_vpToken)

  if (
    v.is(v.looseObject({ proof: v.optional(v.looseObject({ challenge: v.optional(v.string()) })) }), vpToken) &&
    (vpToken['@context'] || vpToken.verifiableCredential)
  ) {
    if (!vpToken.proof?.challenge) {
      throw new Oauth2Error(
        'Failed to parse presentation from vp_token. LDP presentation is missing the proof.challenge parameter.'
      )
    }

    return {
      format: 'ldp_vp',
      presentation: vpToken,
      path: options.path,
      nonce: vpToken?.proof?.challenge,
    }
  }

  if (v.is(v.record(v.string(), v.unknown()), vpToken) && (vpToken.schema_id || vpToken.cred_def_id)) {
    // TODO: HOW TO GET THE NONCE?
    return {
      format: 'ac_vp',
      presentation: vpToken,
      path: options.path,
    }
  }

  if (typeof vpToken !== 'string') {
    throw new Oauth2Error(
      `Could not parse vp_token. Expected a string since the vp_token is neither a ldp_vp nor an ac_vp. Received: ${typeof vpToken}`
    )
  }

  if (vpToken.includes('~')) {
    const split = vpToken.split('~')
    const keyBindingJwt = split[split.length - 1]
    let nonce: string | undefined
    try {
      const decoded = decodeJwt({ jwt: keyBindingJwt })
      nonce = decoded.payload.nonce
    } catch (error) {
      nonce = undefined
    }

    return {
      format: 'dc+sd-jwt',
      presentation: vpToken,
      path: options.path,
    }
  }

  if (v.is(vCompactJwt, vpToken)) {
    let nonce: string | undefined
    try {
      const decoded = decodeJwt({ jwt: vpToken })
      nonce = decoded.payload.nonce
    } catch (error) {
      nonce = undefined
    }

    return {
      format: 'jwt_vp_json',
      presentation: vpToken,
      path: options.path,
      nonce,
    }
  }

  // if it is a string, and neither of the above, we assume it is a mso_mdoc presentation
  // TODO: HOW TO GET THE NONCE?
  return {
    format: 'mso_mdoc',
    presentation: vpToken,
    path: options.path,
  }
}
