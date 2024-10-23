import * as v from 'valibot'
import { expect, test } from 'vitest'
import { vCredentialRequest } from '../../../credential-request/v-credential-request'

test('should correctly parse credential request', () => {
  const parseResult = v.safeParse(vCredentialRequest, {
    format: 'vc+sd-jwt',
    vct: 'https://metadata.paradym.id/types/6fTEgFULv2-EmployeeBadge',
    proof: {
      proof_type: 'jwt',
      jwt: 'ey....',
    },
    proofs: undefined,
  })

  expect(parseResult).toStrictEqual({
    issues: undefined,
    output: {
      format: 'vc+sd-jwt',
      proof: {
        jwt: 'ey....',
        proof_type: 'jwt',
      },
      proofs: undefined,
      vct: 'https://metadata.paradym.id/types/6fTEgFULv2-EmployeeBadge',
    },
    success: true,
    typed: true,
  })
})
