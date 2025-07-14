import { HashAlgorithm, Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { describe, expect, test } from 'vitest'
import { callbacks } from '../../../oauth2/tests/util.mjs'
import { verifyTransactionData } from './verify-transaction-data.js'

describe('Verify transaction data', () => {
  test('succesfully matches with a single credential and transaction data entry', async () => {
    const transactionData = Buffer.from(
      JSON.stringify({
        type: 'qes',
        credential_ids: ['one'],
        transaction_data_hashes_alg: ['sha-256'],
      })
    ).toString('base64url')

    const verifiedMatches = await verifyTransactionData({
      callbacks,
      transactionData: [transactionData],
      credentials: {
        one: [
          {
            transaction_data_hashes: [
              'random',
              Buffer.from(callbacks.hash(Buffer.from(transactionData), HashAlgorithm.Sha256)).toString('base64url'),
            ],
            transaction_data_hashes_alg: 'sha-256',
          },
          {
            transaction_data_hashes: [
              Buffer.from(callbacks.hash(Buffer.from(transactionData), HashAlgorithm.Sha256)).toString('base64url'),
            ],
            transaction_data_hashes_alg: 'sha-256',
          },
        ],
      },
    })

    expect(verifiedMatches).toEqual([
      {
        credentialId: 'one',
        presentations: [
          {
            presentationIndex: 0,
            credentialHashIndex: 1,
            hash: Buffer.from(callbacks.hash(Buffer.from(transactionData), HashAlgorithm.Sha256)).toString('base64url'),
            hashAlg: 'sha-256',
          },
          {
            presentationIndex: 1,
            credentialHashIndex: 0,
            hash: Buffer.from(callbacks.hash(Buffer.from(transactionData), HashAlgorithm.Sha256)).toString('base64url'),
            hashAlg: 'sha-256',
          },
        ],
        transactionDataEntry: {
          transactionDataIndex: 0,
          encoded: transactionData,
          transactionData: {
            credential_ids: ['one'],
            transaction_data_hashes_alg: ['sha-256'],
            type: 'qes',
          },
        },
      },
    ])
  })

  test('succesfully matches with multiple credentials and multiple transaction data entries', async () => {
    const transactionData = Buffer.from(
      JSON.stringify({
        type: 'qes',
        credential_ids: ['one', 'two'],
        transaction_data_hashes_alg: ['sha-256'],
      })
    ).toString('base64url')

    const transactionData2 = Buffer.from(
      JSON.stringify({
        type: 'qes',
        credential_ids: ['three', 'two'],
      })
    ).toString('base64url')

    const verifiedMatches = await verifyTransactionData({
      callbacks,
      transactionData: [transactionData, transactionData2],
      credentials: {
        three: [
          {
            transaction_data_hashes: [
              Buffer.from(callbacks.hash(Buffer.from(transactionData2), HashAlgorithm.Sha256)).toString('base64url'),
            ],
          },
        ],
        two: [
          {
            transaction_data_hashes: [
              'random',
              Buffer.from(callbacks.hash(Buffer.from(transactionData), HashAlgorithm.Sha256)).toString('base64url'),
            ],
            transaction_data_hashes_alg: 'sha-256',
          },
        ],
      },
    })

    expect(verifiedMatches).toEqual([
      {
        credentialId: 'two',
        presentations: [
          {
            presentationIndex: 0,
            credentialHashIndex: 1,
            hash: Buffer.from(callbacks.hash(Buffer.from(transactionData), HashAlgorithm.Sha256)).toString('base64url'),
            hashAlg: 'sha-256',
          },
        ],
        transactionDataEntry: {
          transactionDataIndex: 0,
          encoded: transactionData,
          transactionData: {
            credential_ids: ['one', 'two'],
            transaction_data_hashes_alg: ['sha-256'],
            type: 'qes',
          },
        },
      },
      {
        credentialId: 'three',
        presentations: [
          {
            presentationIndex: 0,
            credentialHashIndex: 0,
            hash: Buffer.from(callbacks.hash(Buffer.from(transactionData2), HashAlgorithm.Sha256)).toString(
              'base64url'
            ),
            hashAlg: 'sha-256',
          },
        ],
        transactionDataEntry: {
          transactionDataIndex: 1,
          encoded: transactionData2,
          transactionData: {
            credential_ids: ['three', 'two'],
            type: 'qes',
          },
        },
      },
    ])
  })

  test('throws an error when the transaction data hash cannot be found', async () => {
    const transactionData = Buffer.from(
      JSON.stringify({
        type: 'qes',
        credential_ids: ['one', 'two'],
        transaction_data_hashes_alg: ['sha-256'],
      })
    ).toString('base64url')

    const transactionData2 = Buffer.from(
      JSON.stringify({
        type: 'qes',
        credential_ids: ['three', 'two'],
      })
    ).toString('base64url')

    await expect(
      verifyTransactionData({
        callbacks,
        transactionData: [transactionData, transactionData2],
        credentials: {
          two: [
            {
              transaction_data_hashes: [
                'random',
                Buffer.from(callbacks.hash(Buffer.from(transactionData), HashAlgorithm.Sha256)).toString('base64url'),
              ],
              transaction_data_hashes_alg: 'sha-256',
            },
          ],
        },
      })
    ).rejects.toThrow(
      new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidTransactionData,
        error_description:
          'Transaction data entry with index 1 for presentation two with index 0 does not have a matching hash in the transaction_data_hashes',
      })
    )
  })

  test('throws an error when the transaction data was hashed using an alg that is not allowed', async () => {
    const transactionData = Buffer.from(
      JSON.stringify({
        type: 'qes',
        credential_ids: ['one', 'two'],
        transaction_data_hashes_alg: ['sha-256'],
      })
    ).toString('base64url')

    const transactionData2 = Buffer.from(
      JSON.stringify({
        type: 'qes',
        credential_ids: ['three', 'two'],
      })
    ).toString('base64url')

    await expect(
      verifyTransactionData({
        callbacks,
        transactionData: [transactionData, transactionData2],
        credentials: {
          two: [
            {
              transaction_data_hashes: [
                'random',
                Buffer.from(callbacks.hash(Buffer.from(transactionData), HashAlgorithm.Sha256)).toString('base64url'),
              ],
              transaction_data_hashes_alg: 'random',
            },
          ],
        },
      })
    ).rejects.toThrow(
      new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidTransactionData,
        error_description:
          "Transaction data entry with index 0 for presentation two with index 0 is hashed using alg 'random'. However transaction data only allows alg values sha-256.",
      })
    )
  })

  test('throws an error when the transaction data was hashed using an alg that is not supported by this library', async () => {
    const transactionData = Buffer.from(
      JSON.stringify({
        type: 'qes',
        credential_ids: ['one', 'two'],
        transaction_data_hashes_alg: ['random'],
      })
    ).toString('base64url')

    const transactionData2 = Buffer.from(
      JSON.stringify({
        type: 'qes',
        credential_ids: ['three', 'two'],
      })
    ).toString('base64url')

    await expect(
      verifyTransactionData({
        callbacks,
        transactionData: [transactionData, transactionData2],
        credentials: {
          two: [
            {
              transaction_data_hashes: [
                'random',
                Buffer.from(callbacks.hash(Buffer.from(transactionData), HashAlgorithm.Sha256)).toString('base64url'),
              ],
              transaction_data_hashes_alg: 'random',
            },
          ],
        },
      })
    ).rejects.toThrow(
      new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidTransactionData,
        error_description:
          "Transaction data entry with index 0 for presentation two with index 0 is hashed using unsupported alg 'random'. This library only supports verification of transaction data hashes using alg values sha-256, sha-384, sha-512. Either verify the hashes outside of this library, or limit the allowed alg values to the ones supported by this library.",
      })
    )
  })
})
