import { Oauth2Error, decodeJwt } from '@openid4vc/oauth2'
import { zCompactJwt } from '@openid4vc/oauth2'
import { isObject, parseIfJson, parseWithErrorHandling } from '@openid4vc/utils'
import { z } from 'zod'
import type { VpToken } from './z-vp-token'

export type VpTokenPresentationParseResult =
  | {
      format: 'dc+sd-jwt' | 'mso_mdoc' | 'jwt_vp_json'
      presentation: string
      path?: string
      nonce?: string
    }
  | {
      format: 'ldp_vp' | 'ac_vp'
      presentation: Record<string, unknown>
      path?: string
      nonce?: string
    }

export interface ParsePresentationsFromVpTokenOptions {
  vpToken: VpToken
}

export function parsePresentationsFromVpToken(
  options: ParsePresentationsFromVpTokenOptions
): [VpTokenPresentationParseResult, ...VpTokenPresentationParseResult[]] {
  const { vpToken: _vpToken } = options
  const vpToken = parseIfJson(_vpToken)

  if (Array.isArray(vpToken)) {
    if (vpToken.length === 0) {
      throw new Oauth2Error('Could not parse vp_token. vp_token is an empty array.')
    }

    return vpToken.map((token, idx) => parseSinglePresentationFromVpToken({ vpToken: token, path: `$[${idx}]` })) as [
      VpTokenPresentationParseResult,
      ...VpTokenPresentationParseResult[],
    ]
  }

  if (typeof vpToken === 'string' || typeof vpToken === 'object') {
    return [parseSinglePresentationFromVpToken({ vpToken, path: '$' })]
  }

  throw new Oauth2Error(
    `Could not parse vp_token. Expected a string or an array of strings. Received: ${typeof vpToken}`
  )
}

export function parseDcqlPresentationFromVpToken(options: { vpToken: unknown }) {
  const { vpToken: _vpToken } = options

  const vpToken = parseIfJson(_vpToken)
  const parsed = parseWithErrorHandling(z.object({}).passthrough(), vpToken)

  const dcqlPresentationRecord = Object.fromEntries(
    Object.entries(parsed).map(([key, value]) => {
      return [key, parseSinglePresentationFromVpToken({ vpToken: value })]
    })
  )

  return dcqlPresentationRecord
}

export function parseSinglePresentationFromVpToken(options: {
  vpToken: unknown
  path?: string
}): VpTokenPresentationParseResult {
  const { vpToken: _vpToken, path } = options

  const vpToken = parseIfJson(_vpToken)
  const zLdpVpProof = z.object({ challenge: z.string().optional() }).passthrough()

  const ldpVpParseResult = z
    .object({
      '@context': z.string().optional(),
      verifiableCredential: z.string().optional(),
      proof: z.union([zLdpVpProof, z.array(zLdpVpProof)]).optional(),
    })
    .passthrough()
    .safeParse(vpToken)
  if (ldpVpParseResult.success && (ldpVpParseResult.data['@context'] || ldpVpParseResult.data.verifiableCredential)) {
    const challenge = Array.isArray(ldpVpParseResult.data.proof)
      ? ldpVpParseResult.data.proof.map((proof) => proof.challenge)
      : ldpVpParseResult.data.proof?.challenge

    // check if all nonces are the same
    if (Array.isArray(challenge)) {
      const allNoncesAreTheSame = challenge.every((nonce) => nonce === challenge[0])
      if (!allNoncesAreTheSame) {
        throw new Oauth2Error(
          'Failed to parse presentation from vp_token. LDP presentation is missing the proof.challenge parameter.'
        )
      }
    }

    if (!challenge) {
      throw new Oauth2Error(
        'Failed to parse presentation from vp_token. LDP presentation is missing the proof.challenge parameter.'
      )
    }

    return {
      format: 'ldp_vp',
      presentation: ldpVpParseResult,
      path,
      nonce: Array.isArray(challenge) ? challenge[0] : challenge,
    }
  }

  if (isObject(vpToken) && (vpToken.schema_id || vpToken.cred_def_id)) {
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

  const result = zCompactJwt.safeParse(vpToken)
  if (result.success) {
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
