import { Oid4vciError } from '../error/Oid4vciError'
import {
  vJwtVcJsonCredentialIssuerMetadata,
  vJwtVcJsonLdCredentialIssuerMetadata,
  vLdpVcCredentialIssuerMetadata,
  vMsoMdocCredentialIssuerMetadata,
  vSdJwtVcCredentialIssuerMetadata,
} from '../formats/credential'
import type { IssuerMetadataResult } from '../metadata/fetch-issuer-metadata'
import type { CredentialRequestWithFormats } from './v-credential-request'

export interface GetCredentialRequestFormatPayloadForCredentialConfigurationIdOptions {
  /**
   * The credential configuration id to get the format payload for
   */
  credentialConfigurationId: string

  /**
   * Metadata of the credential issuer and authorization servers.
   */
  issuerMetadata: IssuerMetadataResult
}

export function getCredentialRequestFormatPayloadForCredentialConfigurationId(
  options: GetCredentialRequestFormatPayloadForCredentialConfigurationIdOptions
): CredentialRequestWithFormats {
  const credentialConfiguration =
    options.issuerMetadata.credentialIssuer.credential_configurations_supported[options.credentialConfigurationId]

  if (!credentialConfiguration) {
    throw new Oid4vciError(
      `Could not find credential configuration with id '${options.credentialConfigurationId}' in metadata of credential issuer '${options.issuerMetadata.credentialIssuer.credential_issuer}'.`
    )
  }

  if (vSdJwtVcCredentialIssuerMetadata.safeParse(credentialConfiguration).success) {
    return {
      format: credentialConfiguration.format,
      vct: credentialConfiguration.vct,
    }
  }

  if (vMsoMdocCredentialIssuerMetadata.safeParse(credentialConfiguration).success) {
    return {
      format: credentialConfiguration.format,
      doctype: credentialConfiguration.doctype,
    }
  }

  if (vLdpVcCredentialIssuerMetadata.safeParse(credentialConfiguration).success) {
    return {
      format: credentialConfiguration.format,
      credential_definition: {
        '@context': credentialConfiguration.credential_definition['@context'],
        type: credentialConfiguration.credential_definition.type,
      },
    }
  }

  if (vJwtVcJsonLdCredentialIssuerMetadata.safeParse(credentialConfiguration).success) {
    return {
      format: credentialConfiguration.format,
      credential_definition: {
        '@context': credentialConfiguration.credential_definition['@context'],
        type: credentialConfiguration.credential_definition.type,
      },
    }
  }

  if (vJwtVcJsonCredentialIssuerMetadata.safeParse(credentialConfiguration).success) {
    return {
      format: credentialConfiguration.format,
      credential_definition: {
        type: credentialConfiguration.credential_definition.type,
      },
    }
  }

  throw new Oid4vciError(
    `Unknown format '${credentialConfiguration.format}' in credential configuration with id '${options.credentialConfigurationId}' for credential issuer '${options.issuerMetadata.credentialIssuer.credential_issuer}'`
  )
}
