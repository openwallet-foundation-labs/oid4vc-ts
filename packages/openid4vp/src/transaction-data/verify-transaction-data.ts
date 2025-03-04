import {
  type CallbackContext,
  HashAlgorithm,
  Oauth2ErrorCodes,
  Oauth2ServerErrorResponseError,
} from '@openid4vc/oauth2'
import { decodeUtf8String, encodeToBase64Url } from '@openid4vc/utils'
import { type ParsedTransactionDataEntry, parseTransactionData } from './parse-transaction-data'

export interface TransactionDataHashesCredentials {
  /**
   * credentialId is the pex input descriptor id
   * or dcql credential query id
   *
   * The values must be an array of transaction data hashes
   */
  [credentialId: string]:
    | {
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
      }
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
  hash: string
  hashAlg: HashAlgorithm
  credentialHashIndex: number
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
    const transactionDataHashesCredential = credentials[credentialId]
    if (!transactionDataHashesCredential) continue

    const alg = transactionDataHashesCredential.transaction_data_hashes_alg ?? 'sha-256'
    const hash = hashes[alg as HashAlgorithm]

    if (!allowedAlgs.includes(alg)) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidTransactionData,
        error_description: `Transaction data entry with index ${entry.transactionDataIndex} is hashed using alg '${alg}'. However transaction data only allows alg values ${allowedAlgs.join(', ')}.`,
      })
    }

    // This is an error of this library.
    if (!hash) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidTransactionData,
        error_description: `Transaction data entry with index ${entry.transactionDataIndex} is hashed using unsupported alg '${alg}'. This library only supports verification of transaction data hashes using alg values ${Object.values(HashAlgorithm).join(', ')}. Either verify the hashes outside of this library, or limit the allowed alg values to the ones supported by this library.`,
      })
    }

    const credentialHashIndex = transactionDataHashesCredential.transaction_data_hashes.indexOf(hash)
    if (credentialHashIndex !== -1) {
      return {
        transactionDataEntry: entry,
        credentialId,
        hash,
        hashAlg: alg as HashAlgorithm,
        credentialHashIndex,
      }
    }
  }

  // No matches were found
  throw new Oauth2ServerErrorResponseError({
    error: Oauth2ErrorCodes.InvalidTransactionData,
    error_description: `Transaction data entry with index ${entry.transactionDataIndex} does not have a matching hash in any of the submitted credentials`,
  })
}
