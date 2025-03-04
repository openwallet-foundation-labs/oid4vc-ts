import { Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { decodeBase64, encodeToUtf8String, parseIfJson } from '@openid4vc/utils'
import { type TransactionDataEntry, zTransactionData } from './z-transaction-data'

export interface ParseTransactionDataOptions {
  transactionData: string[]
}

export interface ParsedTransactionDataEntry {
  transactionData: TransactionDataEntry
  transactionDataIndex: number
  encoded: string
}

export function parseTransactionData(options: ParseTransactionDataOptions): ParsedTransactionDataEntry[] {
  const { transactionData } = options

  const decoded = transactionData.map((tdEntry) => parseIfJson(encodeToUtf8String(decodeBase64(tdEntry))))

  const parsedResult = zTransactionData.safeParse(decoded)
  if (!parsedResult.success) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidTransactionData,
      error_description: 'Failed to parse transaction data.',
    })
  }

  return parsedResult.data.map((decoded, index) => ({
    transactionData: decoded,
    encoded: transactionData[index],
    transactionDataIndex: index,
  }))
}
