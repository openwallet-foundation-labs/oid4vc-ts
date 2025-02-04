import {
  type BaseSchema,
  decodeBase64,
  encodeToUtf8String,
  parseWithErrorHandling,
  stringToJsonWithErrorHandling,
} from '@openid4vc/utils'
import { Oauth2JwtParseError } from '../../error/Oauth2JwtParseError'
import type { InferSchemaOutput } from './decode-jwt'
import { vJwtHeader } from './v-jwt'

export interface DecodeJwtHeaderOptions<HeaderSchema extends BaseSchema | undefined> {
  /**
   * The comapct encoded jwt
   */
  jwe: string

  /**
   * Schema to use for validating the header. If not provided the
   * default `vJwtHeader` schema will be used
   */
  headerSchema?: HeaderSchema
}

export type DecodeJweResult<HeaderSchema extends BaseSchema | undefined = undefined> = {
  header: InferSchemaOutput<HeaderSchema, typeof vJwtHeader>
}

export function decodeJwtHeader<HeaderSchema extends BaseSchema | undefined = undefined>(
  options: DecodeJwtHeaderOptions<HeaderSchema>
): DecodeJweResult<HeaderSchema> {
  const jwtParts = options.jwe.split('.')
  if (jwtParts.length <= 2) {
    throw new Oauth2JwtParseError('Jwt is not a valid jwt, unable to decode')
  }

  let headerJson: Record<string, unknown>
  try {
    headerJson = stringToJsonWithErrorHandling(
      encodeToUtf8String(decodeBase64(jwtParts[0])),
      'Unable to parse jwt header to JSON'
    )
  } catch (error) {
    throw new Oauth2JwtParseError('Error parsing JWT')
  }

  const header = parseWithErrorHandling(options.headerSchema ?? vJwtHeader, headerJson)

  return {
    header,
  }
}
