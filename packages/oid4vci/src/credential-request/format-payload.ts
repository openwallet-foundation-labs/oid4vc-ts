import { zIs } from '@openid4vc/utils'
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

  if (zIs(vSdJwtVcCredentialIssuerMetadata, credentialConfiguration)) {
    return {
      format: credentialConfiguration.format,
      vct: credentialConfiguration.vct,
    }
  }

  if (zIs(vMsoMdocCredentialIssuerMetadata, credentialConfiguration)) {
    return {
      format: credentialConfiguration.format,
      doctype: credentialConfiguration.doctype,
    }
  }

  if (zIs(vLdpVcCredentialIssuerMetadata, credentialConfiguration)) {
    return {
      format: credentialConfiguration.format,
      credential_definition: {
        '@context': credentialConfiguration.credential_definition['@context'],
        type: credentialConfiguration.credential_definition.type,
      },
    }
  }

  if (zIs(vJwtVcJsonLdCredentialIssuerMetadata, credentialConfiguration)) {
    return {
      format: credentialConfiguration.format,
      credential_definition: {
        '@context': credentialConfiguration.credential_definition['@context'],
        type: credentialConfiguration.credential_definition.type,
      },
    }
  }

  if (zIs(vJwtVcJsonCredentialIssuerMetadata, credentialConfiguration)) {
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
