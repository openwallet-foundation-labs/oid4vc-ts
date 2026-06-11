import { Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'

export type JarMetadata = {
  ProtectedBy: 'signature' | 'signature_encryption'
  SendBy: 'value' | 'reference'
}

export interface ValidateJarRequestAgainstSessionOptions {
  jarMetadata: JarMetadata
  jarSessionMetadata: JarMetadata
}

/**
 * Validates a JAR (JWT Authorization Request) request by comparing the provided (actual) metadata
 * with the jar session metadata.
 *
 * @param input - The input object containing the session ID and the JAR metadata.
 * @param input.jarMeta - The actual (received) JAR request metadata.
 * @param input.jarSessionMeta - The session metadata.
 *
 * @returns A promise that resolves to the session metadata if validation is successful.
 *
 * @throws {JarInvalidRequestObjectError} If the `protected_by` or `send_by` values in the JAR metadata
 * do not match the corresponding values in the session metadata.
 */
export async function validateJarRequestAgainstSession(options: ValidateJarRequestAgainstSessionOptions) {
  const { jarMetadata, jarSessionMetadata } = options

  if (jarSessionMetadata.ProtectedBy !== jarMetadata.ProtectedBy) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequestObject,
      error_description: `The 'protected_by' value of the JAR request does not match the value of the session.`,
    })
  }

  if (jarSessionMetadata.SendBy !== jarMetadata.SendBy) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequestObject,
      error_description: `The 'send_by' value of the JAR request does not match the value of the session.`,
    })
  }
}
