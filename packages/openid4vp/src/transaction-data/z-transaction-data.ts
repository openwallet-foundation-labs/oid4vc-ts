import { z } from 'zod'

export const zTransactionEntry = z
  .object({
    type: z.string(),
    credential_ids: z.array(z.string()).nonempty(),
    transaction_data_hashes_alg: z.array(z.string()).optional(),
  })
  .passthrough()
export type TransactionDataEntry = z.infer<typeof zTransactionEntry>

export const zTransactionData = z.array(zTransactionEntry)
export type TransactionData = z.infer<typeof zTransactionData>
