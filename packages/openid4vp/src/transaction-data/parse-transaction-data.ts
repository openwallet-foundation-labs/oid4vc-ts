import { decodeBase64, encodeToUtf8String, parseIfJson, parseWithErrorHandling } from '@openid4vc/utils'
import { type TransactionData, zTransactionData } from './z-transaction-data'

export interface ParseTransactionDataOptions {
  transactionData: string[]
}

export function parseTransactionData(options: ParseTransactionDataOptions): TransactionData {
  const { transactionData } = options
  const decoded = transactionData.map((tdEntry) => parseIfJson(encodeToUtf8String(decodeBase64(tdEntry as string))))
  const parsed = parseWithErrorHandling(zTransactionData, decoded, 'Failed to parse transaction data.')
  return parsed
}
