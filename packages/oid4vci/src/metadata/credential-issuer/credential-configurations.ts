import { Oid4vcError } from '../../error/Oid4vcError'
import type { IssuerMetadataResult } from '../fetch-issuer-metadata'

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

export function extractScopesForCredentialConfigurationIds(options: ExtractScopesForCredentialConfigurationIdsOptions) {
  const scopes = new Set<string>()

  for (const credentialConfigurationId of options.credentialConfigurationIds) {
    const credentialConfiguration =
      options.issuerMetadata.credentialIssuer.credential_configurations_supported[credentialConfigurationId]

    if (!credentialConfiguration) {
      throw new Oid4vcError(
        `Credential configuration with id '${credentialConfigurationId}' not found in metadata from credential issuer '${options.issuerMetadata.credentialIssuer.credential_issuer}'`
      )
    }

    const scope = credentialConfiguration.scope
    if (scope) scopes.add(scope)
    else if (!scope && options.throwOnConfigurationWithoutScope) {
      throw new Oid4vcError(
        `Credential configuration with id '${credentialConfigurationId}' does not have a 'scope' configured, and 'throwOnConfigurationWithoutScope' was enabled.`
      )
    }
  }

  return Array.from(scopes)
}
