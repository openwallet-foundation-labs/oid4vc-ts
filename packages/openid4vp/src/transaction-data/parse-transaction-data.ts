import { Oauth2Error } from '@openid4vc/oauth2'
import { decodeBase64, encodeToUtf8String } from '@openid4vc/utils'
import { parseIfJson } from '@openid4vc/utils'
import * as v from 'valibot'
import { type TransactionData, vTransactionData } from './v-transaction-data'

export function parseTransactionData(transactionData: string[]): TransactionData {
  const decoded = transactionData.map((tdEntry) => parseIfJson(encodeToUtf8String(decodeBase64(tdEntry))))
  const parsed = v.safeParse(vTransactionData, decoded)

  if (!parsed.success) {
    throw new Oauth2Error('Failed to parse transaction data.')
  }

  return parsed.output
}
