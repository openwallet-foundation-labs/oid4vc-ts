import { Oauth2Error } from '@openid4vc/oauth2'
import { ValidationError } from '@openid4vc/utils'
import type z from 'zod'
import { Openid4vciError } from '../../error/Openid4vciError'
import type { IssuerMetadataResult } from '../fetch-issuer-metadata'
import {
  type IssuerMetadataClaimsDescription,
  zCredentialConfigurationSupportedClaimsDraft14,
} from './z-claims-description'
import {
  type CredentialConfigurationsSupported,
  zCredentialConfigurationSupportedDraft11ToV1,
} from './z-credential-issuer-metadata'

export interface ExtractScopesForCredentialConfigurationIdsOptions {
  /**
   * The credential configuration ids to extract the scope from
   */
  credentialConfigurationIds: string[]

  /**
   * Whether to throw an error if the corresponding credential configuration
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
  credentialsSupported: Array<z.input<typeof zCredentialConfigurationSupportedDraft11ToV1>>
) {
  const credentialConfigurationsSupported: CredentialConfigurationsSupported = {}

  for (let index = 0; index < credentialsSupported.length; index++) {
    const credentialSupported = credentialsSupported[index]
    if (!credentialSupported.id) {
      throw new Openid4vciError(
        `Credential supported at index '${index}' does not have an 'id' property. Credential configuration requires the 'id' property as key`
      )
    }

    const parseResult = zCredentialConfigurationSupportedDraft11ToV1.safeParse(credentialSupported)
    if (!parseResult.success) {
      throw new ValidationError(
        `Error transforming credential supported with id '${credentialSupported.id}' to credential configuration supported format`,
        parseResult.error
      )
    }

    credentialConfigurationsSupported[credentialSupported.id] = parseResult.data
  }

  return credentialConfigurationsSupported
}

/**
 * Transforms draft 14 claims object syntax to the new array-based claims description syntax
 *
 * @param claims - The claims object in draft 14 format
 * @returns Array of claims descriptions or undefined if validation fails
 */
export function claimsObjectToClaimsArray(claims: unknown): Array<IssuerMetadataClaimsDescription> | undefined {
  // Validate input
  const parseResult = zCredentialConfigurationSupportedClaimsDraft14.safeParse(claims)
  if (!parseResult.success) {
    return undefined
  }

  const result: Array<IssuerMetadataClaimsDescription> = []

  /**
   * Recursively process claims object, building up the path from parent keys
   */
  function processClaimsObject(
    claimsObj: Record<string, unknown>,
    parentPath: Array<string | number | null> = []
  ): void {
    for (const [key, value] of Object.entries(claimsObj)) {
      const currentPath = [...parentPath, key]

      // Check if this is a leaf node (has claim properties like mandatory, value_type, display)
      if (
        value &&
        typeof value === 'object' &&
        !Array.isArray(value) &&
        ('mandatory' in value || 'value_type' in value || 'display' in value)
      ) {
        const claimValue = value as Record<string, unknown>

        // Create the claim description
        const claimDescription: IssuerMetadataClaimsDescription = {
          path: currentPath as [string | number | null, ...(string | number | null)[]],
        }

        // Add optional properties
        if (typeof claimValue.mandatory === 'boolean') {
          claimDescription.mandatory = claimValue.mandatory
        }

        if (Array.isArray(claimValue.display)) {
          claimDescription.display = claimValue.display as Array<{
            name?: string
            locale?: string
          }>
        }

        // Note: value_type is not included in the new syntax

        result.push(claimDescription)

        // Check if there are nested claims (excluding the known properties)
        const nestedClaims = Object.entries(claimValue).filter(
          ([k]) => k !== 'mandatory' && k !== 'value_type' && k !== 'display'
        )

        if (nestedClaims.length > 0) {
          const nestedObj = Object.fromEntries(nestedClaims)
          processClaimsObject(nestedObj, currentPath)
        }
      } else if (value && typeof value === 'object' && !Array.isArray(value)) {
        // This is a nested object without claim properties, recurse
        processClaimsObject(value as Record<string, unknown>, currentPath)
      }
    }
  }

  processClaimsObject(parseResult.data)

  return result
}
