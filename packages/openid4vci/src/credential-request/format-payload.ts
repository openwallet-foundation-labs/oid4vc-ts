import { zIs } from '@openid4vc/utils'
import { Openid4vciError } from '../error/Openid4vciError'
import {
  zJwtVcJsonCredentialIssuerMetadata,
  zJwtVcJsonLdCredentialIssuerMetadata,
  zLdpVcCredentialIssuerMetadata,
  zMsoMdocCredentialIssuerMetadata,
  zSdJwtVcCredentialIssuerMetadata,
} from '../formats/credential'
import type { IssuerMetadataResult } from '../metadata/fetch-issuer-metadata'
import type { CredentialRequestWithFormats } from './z-credential-request'

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
    throw new Openid4vciError(
      `Could not find credential configuration with id '${options.credentialConfigurationId}' in metadata of credential issuer '${options.issuerMetadata.credentialIssuer.credential_issuer}'.`
    )
  }

  if (zIs(zSdJwtVcCredentialIssuerMetadata, credentialConfiguration)) {
    return {
      format: credentialConfiguration.format,
      vct: credentialConfiguration.vct,
    }
  }

  if (zIs(zMsoMdocCredentialIssuerMetadata, credentialConfiguration)) {
    return {
      format: credentialConfiguration.format,
      doctype: credentialConfiguration.doctype,
    }
  }

  if (zIs(zLdpVcCredentialIssuerMetadata, credentialConfiguration)) {
    return {
      format: credentialConfiguration.format,
      credential_definition: {
        '@context': credentialConfiguration.credential_definition['@context'],
        type: credentialConfiguration.credential_definition.type,
      },
    }
  }

  if (zIs(zJwtVcJsonLdCredentialIssuerMetadata, credentialConfiguration)) {
    return {
      format: credentialConfiguration.format,
      credential_definition: {
        '@context': credentialConfiguration.credential_definition['@context'],
        type: credentialConfiguration.credential_definition.type,
      },
    }
  }

  if (zIs(zJwtVcJsonCredentialIssuerMetadata, credentialConfiguration)) {
    return {
      format: credentialConfiguration.format,
      credential_definition: {
        type: credentialConfiguration.credential_definition.type,
      },
    }
  }

  throw new Openid4vciError(
    `Unknown format '${credentialConfiguration.format}' in credential configuration with id '${options.credentialConfigurationId}' for credential issuer '${options.issuerMetadata.credentialIssuer.credential_issuer}'`
  )
}
