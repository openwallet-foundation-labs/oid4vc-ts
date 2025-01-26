import { Oauth2Error } from '@openid4vc/oauth2'

export type JarMeta = {
  ProtectedBy: 'signature' | 'signature_encryption'
  SendBy: 'value' | 'reference'
}

export interface ValidateJarRequestAgainstSessionOptions {
  jarMeta: JarMeta
  jarSessionMeta: JarMeta
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
  const { jarMeta, jarSessionMeta } = options

  if (jarSessionMeta.ProtectedBy !== jarMeta.ProtectedBy) {
    throw new Oauth2Error(`The protected_by value does not match the session's protected_by value.`)
  }

  if (jarSessionMeta.SendBy !== jarMeta.SendBy) {
    throw new Oauth2Error(`The send_by value does not match the session's send_by value.`)
  }
}
