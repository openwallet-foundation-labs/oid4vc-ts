import { z } from 'zod'

export const zTransactionEntry = z
  .object({
    type: z.string(),
    credential_ids: z.tuple([z.string()], z.string()),

    // SD-JWT VC specific
    transaction_data_hashes_alg: z.tuple([z.string()], z.string()).optional(),
  })
  .loose()
export type TransactionDataEntry = z.infer<typeof zTransactionEntry>

export const zTransactionData = z.array(zTransactionEntry)
export type TransactionData = z.infer<typeof zTransactionData>
