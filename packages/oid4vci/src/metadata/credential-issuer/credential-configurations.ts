import { Oauth2Error } from '@openid4vc/oauth2'
import { ValidationError } from '@openid4vc/utils'
import { Oid4vciError } from '../../error/Oid4vciError'
import type { IssuerMetadataResult } from '../fetch-issuer-metadata'
import {
  type CredentialConfigurationsSupported,
  vCredentialConfigurationSupportedDraft11To14,
} from './v-credential-issuer-metadata'
import type z from 'zod'

export interface ExtractScopesForCredentialConfigurationIdsOptions {
  /**
   * The credential configuration ids to extract the scope from
   */
  credentialConfigurationIds: string[]

  /**
   * Wheter to throw an error if the correspdong credential configuration
   * for a provided credential configuration id has no scope.
   *
   * @default false
   */
  throwOnConfigurationWithoutScope?: boolean

  /**
   * The issuer metadata
   */
  issuerMetadata: IssuerMetadataResult
}

export function extractScopesForCredentialConfigurationIds(
  options: ExtractScopesForCredentialConfigurationIdsOptions
): string[] | undefined {
  const scopes = new Set<string>()

  for (const credentialConfigurationId of options.credentialConfigurationIds) {
    const credentialConfiguration =
      options.issuerMetadata.credentialIssuer.credential_configurations_supported[credentialConfigurationId]

    if (!credentialConfiguration) {
      throw new Oauth2Error(
        `Credential configuration with id '${credentialConfigurationId}' not found in metadata from credential issuer '${options.issuerMetadata.credentialIssuer.credential_issuer}'`
      )
    }

    const scope = credentialConfiguration.scope
    if (scope) scopes.add(scope)
    else if (!scope && options.throwOnConfigurationWithoutScope) {
      throw new Oauth2Error(
        `Credential configuration with id '${credentialConfigurationId}' does not have a 'scope' configured, and 'throwOnConfigurationWithoutScope' was enabled.`
      )
    }
  }

  return scopes.size > 0 ? Array.from(scopes) : undefined
}

/**
 * Transforms draft 11 credentials supported syntax to credential configurations supported
 *
 * @throws if a credentials supported entry without id is passed
 * @throws if a credentials supported entry with invalid structure or format specific properties is passed
 */
export function credentialsSupportedToCredentialConfigurationsSupported(
  credentialsSupported: Array<z.infer<typeof vCredentialConfigurationSupportedDraft11To14>>
) {
  const credentialConfigurationsSupported: CredentialConfigurationsSupported = {}

  for (let index = 0; index < credentialsSupported.length; index++) {
    const credentialSupported = credentialsSupported[index]
    if (!credentialSupported.id) {
      throw new Oid4vciError(
        `Credential supported at index '${index}' does not have an 'id' property. Credential configuration requires the 'id' property as key`
      )
    }

    const parseResult = vCredentialConfigurationSupportedDraft11To14.safeParse(credentialSupported)
    if (!parseResult.success) {
      throw new ValidationError(
        `Error transforming credential supported with id '${credentialSupported.id}' to credential configuration supported format`,
        parseResult.error
      )
    }

    credentialConfigurationsSupported[credentialSupported.id] = parseResult.output
  }

  return credentialConfigurationsSupported
}
