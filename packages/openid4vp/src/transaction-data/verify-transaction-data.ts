import {
  type CallbackContext,
  HashAlgorithm,
  Oauth2ErrorCodes,
  Oauth2ServerErrorResponseError,
} from '@openid4vc/oauth2'
import { decodeUtf8String, encodeToBase64Url, type NonEmptyArray } from '@openid4vc/utils'
import { type ParsedTransactionDataEntry, parseTransactionData } from './parse-transaction-data'

export interface TransactionDataHashesCredentials {
  /**
   * credentialId is the pex input descriptor id
   * or dcql credential query id.
   *
   * The values must be an array of transaction data hashes
   */
  [credentialId: string]:
    | NonEmptyArray<{
        /**
         * The hashes of the transaction data
         */
        transaction_data_hashes: string[]

        /**
         * The transaction data hash alg. If not provided
         * in the presentation, the default value of sha256
         * is used.
         */
        transaction_data_hashes_alg?: string
      }>
    | undefined
}

export interface VerifyTransactionDataOptions {
  transactionData: string[]
  credentials: TransactionDataHashesCredentials
  callbacks: Pick<CallbackContext, 'hash'>
}

export async function verifyTransactionData(
  options: VerifyTransactionDataOptions
): Promise<VerifiedTransactionDataEntry[]> {
  const parsedTransactionData = parseTransactionData({
    transactionData: options.transactionData,
  })

  const matchedEntries: Array<VerifiedTransactionDataEntry> = []
  for (const parsedEntry of parsedTransactionData) {
    const matchedEntry = await verifyTransactionDataEntry({
      entry: parsedEntry,
      callbacks: options.callbacks,
      credentials: options.credentials,
    })

    matchedEntries.push(matchedEntry)
  }

  return matchedEntries
}

export interface VerifiedTransactionDataEntry {
  transactionDataEntry: ParsedTransactionDataEntry
  credentialId: string

  presentations: NonEmptyArray<{
    presentationIndex: number
    hash: string
    hashAlg: HashAlgorithm
    credentialHashIndex: number
  }>
}

async function verifyTransactionDataEntry({
  entry,
  credentials,
  callbacks,
}: {
  entry: ParsedTransactionDataEntry
  credentials: TransactionDataHashesCredentials
  callbacks: Pick<CallbackContext, 'hash'>
}): Promise<VerifiedTransactionDataEntry> {
  const allowedAlgs = entry.transactionData.transaction_data_hashes_alg ?? ['sha-256']
  const supportedAlgs: HashAlgorithm[] = allowedAlgs.filter((alg): alg is HashAlgorithm =>
    Object.values(HashAlgorithm).includes(alg as HashAlgorithm)
  )

  const hashes: { [key in HashAlgorithm]?: string } = {}
  for (const alg of supportedAlgs) {
    hashes[alg] = encodeToBase64Url(await callbacks.hash(decodeUtf8String(entry.encoded), alg))
  }

  for (const credentialId of entry.transactionData.credential_ids) {
    const transactionDataHashesCredentials = credentials[credentialId]
    if (!transactionDataHashesCredentials) continue

    const presentations: VerifiedTransactionDataEntry['presentations'][number][] = []

    for (const transactionDataHashesCredential of transactionDataHashesCredentials) {
      const alg = transactionDataHashesCredential.transaction_data_hashes_alg ?? 'sha-256'
      const hash = hashes[alg as HashAlgorithm]
      const presentationIndex = transactionDataHashesCredentials.indexOf(transactionDataHashesCredential)

      if (!allowedAlgs.includes(alg)) {
        throw new Oauth2ServerErrorResponseError({
          error: Oauth2ErrorCodes.InvalidTransactionData,
          error_description: `Transaction data entry with index ${entry.transactionDataIndex} for presentation ${credentialId} with index ${presentationIndex} is hashed using alg '${alg}'. However transaction data only allows alg values ${allowedAlgs.join(', ')}.`,
        })
      }

      if (!hash) {
        // This is an error of this library.
        throw new Oauth2ServerErrorResponseError({
          error: Oauth2ErrorCodes.InvalidTransactionData,
          error_description: `Transaction data entry with index ${entry.transactionDataIndex} for presentation ${credentialId} with index ${presentationIndex} is hashed using unsupported alg '${alg}'. This library only supports verification of transaction data hashes using alg values ${Object.values(HashAlgorithm).join(', ')}. Either verify the hashes outside of this library, or limit the allowed alg values to the ones supported by this library.`,
        })
      }

      const credentialHashIndex = transactionDataHashesCredential.transaction_data_hashes.indexOf(hash)

      if (credentialHashIndex === -1) {
        // No matches were found
        throw new Oauth2ServerErrorResponseError({
          error: Oauth2ErrorCodes.InvalidTransactionData,
          error_description: `Transaction data entry with index ${entry.transactionDataIndex} for presentation ${credentialId} with index ${presentationIndex} does not have a matching hash in the transaction_data_hashes`,
        })
      }

      presentations.push({
        credentialHashIndex,
        hash,
        hashAlg: alg as HashAlgorithm,
        presentationIndex,
      })
    }

    return {
      transactionDataEntry: entry,
      credentialId,
      presentations: presentations as VerifiedTransactionDataEntry['presentations'],
    }
  }

  // No matches were found
  throw new Oauth2ServerErrorResponseError({
    error: Oauth2ErrorCodes.InvalidTransactionData,
    error_description: `Transaction data entry with index ${entry.transactionDataIndex} does not have a matching hash in any of the submitted credentials`,
  })
}
