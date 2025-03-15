import { http, HttpResponse } from 'msw'
import { setupServer } from 'msw/node'
import { afterAll, afterEach, beforeAll, describe, expect, test } from 'vitest'
import { getSignJwtCallback, callbacks as partialCallbacks } from '../../oauth2/tests/util'
import {
  createOpenid4vpAuthorizationResponse,
  resolveOpenid4vpAuthorizationRequest,
  submitOpenid4vpAuthorizationResponse,
  validateOpenid4vpAuthorizationResponsePayload,
} from '../src'
import { createOpenid4vpAuthorizationRequest } from '../src/authorization-request/create-authorization-request'
import { parseOpenid4VpAuthorizationResponsePayload } from '../src/authorization-response/parse-authorization-response-payload'

const exampleDcqlQuery = {
  credentials: [
    {
      id: 'orgeuuniversity',
      format: 'mso_mdoc',
      meta: { doctype_value: 'org.eu.university' },
      claims: [
        { namespace: 'eu.europa.ec.eudi.pid.1', claim_name: 'name' },
        { namespace: 'eu.europa.ec.eudi.pid.1', claim_name: 'degree' },
        { namespace: 'eu.europa.ec.eudi.pid.1', claim_name: 'date' },
      ],
    },
    {
      id: 'OpenBadgeCredentialDescriptor',
      format: 'dc+sd-jwt',
      meta: { vct_values: ['OpenBadgeCredential'] },
      claims: [{ path: ['university'] }],
    },
  ],
}

const exampleVptoken = {
  orgeuuniversity:
    'uQADZ3ZlcnNpb25jMS4waWRvY3VtZW50c4GjZ2RvY1R5cGVxb3JnLmV1LnVuaXZlcnNpdHlsaXNzdWVyU2lnbmVkuQACam5hbWVTcGFjZXOhd2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xg9gYWGGkaGRpZ2VzdElEA3FlbGVtZW50SWRlbnRpZmllcmRuYW1lbGVsZW1lbnRWYWx1ZWhKb2huIERvZWZyYW5kb21YIEWyJGCZTVxZPQlUipZgJrFHAG953ShscUxOhqcVj5zZ2BhYY6RoZGlnZXN0SUQBcWVsZW1lbnRJZGVudGlmaWVyZmRlZ3JlZWxlbGVtZW50VmFsdWVoYmFjaGVsb3JmcmFuZG9tWCAK5tJW8iDu2_pFMZbncXHsVSoMPB-j6NHzTidrmAwglNgYWGakaGRpZ2VzdElEAnFlbGVtZW50SWRlbnRpZmllcmRkYXRlbGVsZW1lbnRWYWx1ZdkD7GoyMDI1LTAyLTI3ZnJhbmRvbVggHkxQ5P0ym4b-S2YhPULns-6950O_pu1f01YH4KZf7RFqaXNzdWVyQXV0aIRDoQEmogRYMXpEbmFlYVpVV3dVUmpyNVE1TTJnMnVjZjE2bjNwVUx4bzRDaHFuZktYTnJNMk53MUsYIYFZAR4wggEaMIHAoAMCAQICEBe3X5XsrOs2ZhTfjDA0whkwCgYIKoZIzj0EAwIwDTELMAkGA1UEAxMCREUwHhcNMjUwMjI3MDkxOTMzWhcNMjYwMjI3MDkxOTMzWjANMQswCQYDVQQDEwJERTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJaBQfh-jpNhVxqwlTlv39Gm3nkewRvcA4p9TRao8YlC271XGo2ojTBcNh-RX65ql--tNygiJh6BHNhz98VPcVCjAjAAMAoGCCqGSM49BAMCA0kAMEYCIQCx9YNNPzp7YPPdy4k3IVR_XLl6e7bnKS91cGEwArbMzgIhAIuglfUtfZM-ZYoEX1xYB47wMm666Trcykjag1sYMfgZWQIA2BhZAfu5AAZndmVyc2lvbmMxLjBvZGlnZXN0QWxnb3JpdGhtZ1NIQS0yNTZsdmFsdWVEaWdlc3RzoXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMaUAWCAVPsuROLqNqsVsaaCrTJzdHdZ_IznS1nCh1qVKWZ2ezQFYIPeazaLvXv5M-s2h9713AG_QJcCZW-eu6UGzoGI6O9ZnAlggqnuFzR9wHj_51ftmjpqo5s-XIvjoLPw-5sfQ-IGtp1kDWCByQ8dnllyBLPNL1DgHqA0B8yAuvY-EoCVGmEAWMAbeowRYICrRJfwVhE9JJzLpa6tfc1LJ9rvv0sr2OzQ9ot-68CnNbWRldmljZUtleUluZm-5AAFpZGV2aWNlS2V5pAECIAEhWCAakKubHmMGh9_OHyUGEZ8102VOMM6j7C-MlEyHDyYJ1yJYIJbQibZhVZZ2ghRAClhsQO_fXpWcqRQKhriSZ4azbE2oZ2RvY1R5cGVxb3JnLmV1LnVuaXZlcnNpdHlsdmFsaWRpdHlJbmZvuQAEZnNpZ25lZMB0MjAyNS0wMi0yN1QwOToxOTozM1ppdmFsaWRGcm9twHQyMDI1LTAyLTI3VDA5OjE5OjMzWmp2YWxpZFVudGlswHQyMDI2LTAyLTI3VDA5OjE5OjMzWm5leHBlY3RlZFVwZGF0ZfdYQCFznxzCxRUqSe65YB3p1pjTEK7Sma4-JTUhnbwsdmtAoLBv5NMlu54mHj7oGCRBmN3G_un8GeX2opmG78yVdJNsZGV2aWNlU2lnbmVkuQACam5hbWVTcGFjZXPYGEGgamRldmljZUF1dGi5AAJvZGV2aWNlU2lnbmF0dXJlhEOhASag9lhA0kcpmpDK-lGZnNZ_cCjb_CbEz6UZ_MwymXE9r1j9YFrSpoahLj6dkprCZuaS1K79dvSZQTHw23KHzP_JAGFcj2lkZXZpY2VNYWP3ZnN0YXR1cwA',
  OpenBadgeCredentialDescriptor:
    'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSIsImtpZCI6IiN6Nk1rcnpRUEJyNHB5cUM3NzZLS3RyejEzU2NoTTVlUFBic3N1UHVRWmI1dDR1S1EifQ.eyJ2Y3QiOiJPcGVuQmFkZ2VDcmVkZW50aWFsIiwiZGVncmVlIjoiYmFjaGVsb3IiLCJjbmYiOnsia2lkIjoiZGlkOmtleTp6Nk1rcEdSNGdzNFJjM1pwaDR2ajh3Um5qbkF4Z0FQU3hjUjhNQVZLdXRXc3BRemMjejZNa3BHUjRnczRSYzNacGg0dmo4d1Juam5BeGdBUFN4Y1I4TUFWS3V0V3NwUXpjIn0sImlzcyI6ImRpZDprZXk6ejZNa3J6UVBCcjRweXFDNzc2S0t0cnoxM1NjaE01ZVBQYnNzdVB1UVpiNXQ0dUtRIiwiaWF0IjoxNzQwNjQ3OTczLCJfc2QiOlsiSEtyNW1mYkE2OGRZY0JYZTVMRDREdFJHdjVoNWp0NEVDT2JSOWF5VkJCOCIsImlBYS1YVXhGaG1nU0g2SWhTOHZ2cm1TWF95VHJ2ZTQtZjFjTWRPLU41VUUiXSwiX3NkX2FsZyI6InNoYS0yNTYifQ.pP2G3YxexmDGpF-vfb04zMhVLLJGjkiVUiA-I-aLVdhNqzCjexOAu9xQOt0uTGT-4_ly_j66FXR2v4p0z9iyBw~WyI2NTgyNDY2MzM4MjYyODgyMjY2Nzc2MTkiLCJ1bml2ZXJzaXR5IiwiaW5uc2JydWNrIl0~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFZERTQSJ9.eyJpYXQiOjE3NDA2NDc5NzYsIm5vbmNlIjoiNDczODIzNzM5Nzg4MzU1NzEyMTc3MzUwIiwiYXVkIjoieDUwOV9zYW5fZG5zOmxvY2FsaG9zdDoxMjM0IiwidHJhbnNhY3Rpb25fZGF0YV9oYXNoZXMiOlsiWHd5VmQ3d0ZSRWRWV0xwbmk1UU5IZ2dOV1hvMko0TG41OHQyX2VjSjczcyJdLCJ0cmFuc2FjdGlvbl9kYXRhX2hhc2hlc19hbGciOiJzaGEtMjU2Iiwic2RfaGFzaCI6IkJFQ09xRm9OMjM0UldtRzEtTUlSWXl5SnpXTDg1XzRLdTdHNC1KcUl4V0UifQ.ZnDZBS8o_WPsTlvuUO0SnARUIvx1M8t9Fd6TiaQbMtT_0OA7QCvdpisSh9-NfLAb40frAED875W8RI3zi06-DQ',
}

const server = setupServer()

const callbacks = {
  ...partialCallbacks,
  fetch,
  signJwt: getSignJwtCallback([]),
  encryptJwe: () => {
    throw new Error('Not implemented')
  },
  decryptJwe: () => {
    throw new Error('Not implemented')
  },
}

describe('Full E2E openid4vp test', () => {
  beforeAll(() => {
    server.listen()
  })

  afterEach(() => {
    server.resetHandlers()
  })

  afterAll(() => {
    server.close()
  })

  test('openid4vp (unsigned)', async () => {
    callbacks.fetch = fetch
    const authorizationRequestPayload = {
      nonce: 'nonce',
      client_metadata: {},
      response_mode: 'direct_post',
      dcql_query: exampleDcqlQuery,
      response_uri: 'https://example.com/response_uri',
      response_type: 'vp_token',
      client_id: 'client_id',
    } as const

    server.resetHandlers(
      http.post(authorizationRequestPayload.response_uri, async ({ request }) => {
        try {
          const formData = await request.formData()
          const rawResponsePayload = Object.fromEntries(formData.entries())
          expect(rawResponsePayload).toMatchObject({
            vp_token:
              '{"orgeuuniversity":"uQADZ3ZlcnNpb25jMS4waWRvY3VtZW50c4GjZ2RvY1R5cGVxb3JnLmV1LnVuaXZlcnNpdHlsaXNzdWVyU2lnbmVkuQACam5hbWVTcGFjZXOhd2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xg9gYWGGkaGRpZ2VzdElEA3FlbGVtZW50SWRlbnRpZmllcmRuYW1lbGVsZW1lbnRWYWx1ZWhKb2huIERvZWZyYW5kb21YIEWyJGCZTVxZPQlUipZgJrFHAG953ShscUxOhqcVj5zZ2BhYY6RoZGlnZXN0SUQBcWVsZW1lbnRJZGVudGlmaWVyZmRlZ3JlZWxlbGVtZW50VmFsdWVoYmFjaGVsb3JmcmFuZG9tWCAK5tJW8iDu2_pFMZbncXHsVSoMPB-j6NHzTidrmAwglNgYWGakaGRpZ2VzdElEAnFlbGVtZW50SWRlbnRpZmllcmRkYXRlbGVsZW1lbnRWYWx1ZdkD7GoyMDI1LTAyLTI3ZnJhbmRvbVggHkxQ5P0ym4b-S2YhPULns-6950O_pu1f01YH4KZf7RFqaXNzdWVyQXV0aIRDoQEmogRYMXpEbmFlYVpVV3dVUmpyNVE1TTJnMnVjZjE2bjNwVUx4bzRDaHFuZktYTnJNMk53MUsYIYFZAR4wggEaMIHAoAMCAQICEBe3X5XsrOs2ZhTfjDA0whkwCgYIKoZIzj0EAwIwDTELMAkGA1UEAxMCREUwHhcNMjUwMjI3MDkxOTMzWhcNMjYwMjI3MDkxOTMzWjANMQswCQYDVQQDEwJERTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJaBQfh-jpNhVxqwlTlv39Gm3nkewRvcA4p9TRao8YlC271XGo2ojTBcNh-RX65ql--tNygiJh6BHNhz98VPcVCjAjAAMAoGCCqGSM49BAMCA0kAMEYCIQCx9YNNPzp7YPPdy4k3IVR_XLl6e7bnKS91cGEwArbMzgIhAIuglfUtfZM-ZYoEX1xYB47wMm666Trcykjag1sYMfgZWQIA2BhZAfu5AAZndmVyc2lvbmMxLjBvZGlnZXN0QWxnb3JpdGhtZ1NIQS0yNTZsdmFsdWVEaWdlc3RzoXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMaUAWCAVPsuROLqNqsVsaaCrTJzdHdZ_IznS1nCh1qVKWZ2ezQFYIPeazaLvXv5M-s2h9713AG_QJcCZW-eu6UGzoGI6O9ZnAlggqnuFzR9wHj_51ftmjpqo5s-XIvjoLPw-5sfQ-IGtp1kDWCByQ8dnllyBLPNL1DgHqA0B8yAuvY-EoCVGmEAWMAbeowRYICrRJfwVhE9JJzLpa6tfc1LJ9rvv0sr2OzQ9ot-68CnNbWRldmljZUtleUluZm-5AAFpZGV2aWNlS2V5pAECIAEhWCAakKubHmMGh9_OHyUGEZ8102VOMM6j7C-MlEyHDyYJ1yJYIJbQibZhVZZ2ghRAClhsQO_fXpWcqRQKhriSZ4azbE2oZ2RvY1R5cGVxb3JnLmV1LnVuaXZlcnNpdHlsdmFsaWRpdHlJbmZvuQAEZnNpZ25lZMB0MjAyNS0wMi0yN1QwOToxOTozM1ppdmFsaWRGcm9twHQyMDI1LTAyLTI3VDA5OjE5OjMzWmp2YWxpZFVudGlswHQyMDI2LTAyLTI3VDA5OjE5OjMzWm5leHBlY3RlZFVwZGF0ZfdYQCFznxzCxRUqSe65YB3p1pjTEK7Sma4-JTUhnbwsdmtAoLBv5NMlu54mHj7oGCRBmN3G_un8GeX2opmG78yVdJNsZGV2aWNlU2lnbmVkuQACam5hbWVTcGFjZXPYGEGgamRldmljZUF1dGi5AAJvZGV2aWNlU2lnbmF0dXJlhEOhASag9lhA0kcpmpDK-lGZnNZ_cCjb_CbEz6UZ_MwymXE9r1j9YFrSpoahLj6dkprCZuaS1K79dvSZQTHw23KHzP_JAGFcj2lkZXZpY2VNYWP3ZnN0YXR1cwA","OpenBadgeCredentialDescriptor":"eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSIsImtpZCI6IiN6Nk1rcnpRUEJyNHB5cUM3NzZLS3RyejEzU2NoTTVlUFBic3N1UHVRWmI1dDR1S1EifQ.eyJ2Y3QiOiJPcGVuQmFkZ2VDcmVkZW50aWFsIiwiZGVncmVlIjoiYmFjaGVsb3IiLCJjbmYiOnsia2lkIjoiZGlkOmtleTp6Nk1rcEdSNGdzNFJjM1pwaDR2ajh3Um5qbkF4Z0FQU3hjUjhNQVZLdXRXc3BRemMjejZNa3BHUjRnczRSYzNacGg0dmo4d1Juam5BeGdBUFN4Y1I4TUFWS3V0V3NwUXpjIn0sImlzcyI6ImRpZDprZXk6ejZNa3J6UVBCcjRweXFDNzc2S0t0cnoxM1NjaE01ZVBQYnNzdVB1UVpiNXQ0dUtRIiwiaWF0IjoxNzQwNjQ3OTczLCJfc2QiOlsiSEtyNW1mYkE2OGRZY0JYZTVMRDREdFJHdjVoNWp0NEVDT2JSOWF5VkJCOCIsImlBYS1YVXhGaG1nU0g2SWhTOHZ2cm1TWF95VHJ2ZTQtZjFjTWRPLU41VUUiXSwiX3NkX2FsZyI6InNoYS0yNTYifQ.pP2G3YxexmDGpF-vfb04zMhVLLJGjkiVUiA-I-aLVdhNqzCjexOAu9xQOt0uTGT-4_ly_j66FXR2v4p0z9iyBw~WyI2NTgyNDY2MzM4MjYyODgyMjY2Nzc2MTkiLCJ1bml2ZXJzaXR5IiwiaW5uc2JydWNrIl0~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFZERTQSJ9.eyJpYXQiOjE3NDA2NDc5NzYsIm5vbmNlIjoiNDczODIzNzM5Nzg4MzU1NzEyMTc3MzUwIiwiYXVkIjoieDUwOV9zYW5fZG5zOmxvY2FsaG9zdDoxMjM0IiwidHJhbnNhY3Rpb25fZGF0YV9oYXNoZXMiOlsiWHd5VmQ3d0ZSRWRWV0xwbmk1UU5IZ2dOV1hvMko0TG41OHQyX2VjSjczcyJdLCJ0cmFuc2FjdGlvbl9kYXRhX2hhc2hlc19hbGciOiJzaGEtMjU2Iiwic2RfaGFzaCI6IkJFQ09xRm9OMjM0UldtRzEtTUlSWXl5SnpXTDg1XzRLdTdHNC1KcUl4V0UifQ.ZnDZBS8o_WPsTlvuUO0SnARUIvx1M8t9Fd6TiaQbMtT_0OA7QCvdpisSh9-NfLAb40frAED875W8RI3zi06-DQ"}',
          })

          const authorizationResponsePayload = parseOpenid4VpAuthorizationResponsePayload(rawResponsePayload)
          expect(authorizationResponsePayload).toMatchObject({
            vp_token:
              '{"orgeuuniversity":"uQADZ3ZlcnNpb25jMS4waWRvY3VtZW50c4GjZ2RvY1R5cGVxb3JnLmV1LnVuaXZlcnNpdHlsaXNzdWVyU2lnbmVkuQACam5hbWVTcGFjZXOhd2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xg9gYWGGkaGRpZ2VzdElEA3FlbGVtZW50SWRlbnRpZmllcmRuYW1lbGVsZW1lbnRWYWx1ZWhKb2huIERvZWZyYW5kb21YIEWyJGCZTVxZPQlUipZgJrFHAG953ShscUxOhqcVj5zZ2BhYY6RoZGlnZXN0SUQBcWVsZW1lbnRJZGVudGlmaWVyZmRlZ3JlZWxlbGVtZW50VmFsdWVoYmFjaGVsb3JmcmFuZG9tWCAK5tJW8iDu2_pFMZbncXHsVSoMPB-j6NHzTidrmAwglNgYWGakaGRpZ2VzdElEAnFlbGVtZW50SWRlbnRpZmllcmRkYXRlbGVsZW1lbnRWYWx1ZdkD7GoyMDI1LTAyLTI3ZnJhbmRvbVggHkxQ5P0ym4b-S2YhPULns-6950O_pu1f01YH4KZf7RFqaXNzdWVyQXV0aIRDoQEmogRYMXpEbmFlYVpVV3dVUmpyNVE1TTJnMnVjZjE2bjNwVUx4bzRDaHFuZktYTnJNMk53MUsYIYFZAR4wggEaMIHAoAMCAQICEBe3X5XsrOs2ZhTfjDA0whkwCgYIKoZIzj0EAwIwDTELMAkGA1UEAxMCREUwHhcNMjUwMjI3MDkxOTMzWhcNMjYwMjI3MDkxOTMzWjANMQswCQYDVQQDEwJERTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJaBQfh-jpNhVxqwlTlv39Gm3nkewRvcA4p9TRao8YlC271XGo2ojTBcNh-RX65ql--tNygiJh6BHNhz98VPcVCjAjAAMAoGCCqGSM49BAMCA0kAMEYCIQCx9YNNPzp7YPPdy4k3IVR_XLl6e7bnKS91cGEwArbMzgIhAIuglfUtfZM-ZYoEX1xYB47wMm666Trcykjag1sYMfgZWQIA2BhZAfu5AAZndmVyc2lvbmMxLjBvZGlnZXN0QWxnb3JpdGhtZ1NIQS0yNTZsdmFsdWVEaWdlc3RzoXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMaUAWCAVPsuROLqNqsVsaaCrTJzdHdZ_IznS1nCh1qVKWZ2ezQFYIPeazaLvXv5M-s2h9713AG_QJcCZW-eu6UGzoGI6O9ZnAlggqnuFzR9wHj_51ftmjpqo5s-XIvjoLPw-5sfQ-IGtp1kDWCByQ8dnllyBLPNL1DgHqA0B8yAuvY-EoCVGmEAWMAbeowRYICrRJfwVhE9JJzLpa6tfc1LJ9rvv0sr2OzQ9ot-68CnNbWRldmljZUtleUluZm-5AAFpZGV2aWNlS2V5pAECIAEhWCAakKubHmMGh9_OHyUGEZ8102VOMM6j7C-MlEyHDyYJ1yJYIJbQibZhVZZ2ghRAClhsQO_fXpWcqRQKhriSZ4azbE2oZ2RvY1R5cGVxb3JnLmV1LnVuaXZlcnNpdHlsdmFsaWRpdHlJbmZvuQAEZnNpZ25lZMB0MjAyNS0wMi0yN1QwOToxOTozM1ppdmFsaWRGcm9twHQyMDI1LTAyLTI3VDA5OjE5OjMzWmp2YWxpZFVudGlswHQyMDI2LTAyLTI3VDA5OjE5OjMzWm5leHBlY3RlZFVwZGF0ZfdYQCFznxzCxRUqSe65YB3p1pjTEK7Sma4-JTUhnbwsdmtAoLBv5NMlu54mHj7oGCRBmN3G_un8GeX2opmG78yVdJNsZGV2aWNlU2lnbmVkuQACam5hbWVTcGFjZXPYGEGgamRldmljZUF1dGi5AAJvZGV2aWNlU2lnbmF0dXJlhEOhASag9lhA0kcpmpDK-lGZnNZ_cCjb_CbEz6UZ_MwymXE9r1j9YFrSpoahLj6dkprCZuaS1K79dvSZQTHw23KHzP_JAGFcj2lkZXZpY2VNYWP3ZnN0YXR1cwA","OpenBadgeCredentialDescriptor":"eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSIsImtpZCI6IiN6Nk1rcnpRUEJyNHB5cUM3NzZLS3RyejEzU2NoTTVlUFBic3N1UHVRWmI1dDR1S1EifQ.eyJ2Y3QiOiJPcGVuQmFkZ2VDcmVkZW50aWFsIiwiZGVncmVlIjoiYmFjaGVsb3IiLCJjbmYiOnsia2lkIjoiZGlkOmtleTp6Nk1rcEdSNGdzNFJjM1pwaDR2ajh3Um5qbkF4Z0FQU3hjUjhNQVZLdXRXc3BRemMjejZNa3BHUjRnczRSYzNacGg0dmo4d1Juam5BeGdBUFN4Y1I4TUFWS3V0V3NwUXpjIn0sImlzcyI6ImRpZDprZXk6ejZNa3J6UVBCcjRweXFDNzc2S0t0cnoxM1NjaE01ZVBQYnNzdVB1UVpiNXQ0dUtRIiwiaWF0IjoxNzQwNjQ3OTczLCJfc2QiOlsiSEtyNW1mYkE2OGRZY0JYZTVMRDREdFJHdjVoNWp0NEVDT2JSOWF5VkJCOCIsImlBYS1YVXhGaG1nU0g2SWhTOHZ2cm1TWF95VHJ2ZTQtZjFjTWRPLU41VUUiXSwiX3NkX2FsZyI6InNoYS0yNTYifQ.pP2G3YxexmDGpF-vfb04zMhVLLJGjkiVUiA-I-aLVdhNqzCjexOAu9xQOt0uTGT-4_ly_j66FXR2v4p0z9iyBw~WyI2NTgyNDY2MzM4MjYyODgyMjY2Nzc2MTkiLCJ1bml2ZXJzaXR5IiwiaW5uc2JydWNrIl0~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFZERTQSJ9.eyJpYXQiOjE3NDA2NDc5NzYsIm5vbmNlIjoiNDczODIzNzM5Nzg4MzU1NzEyMTc3MzUwIiwiYXVkIjoieDUwOV9zYW5fZG5zOmxvY2FsaG9zdDoxMjM0IiwidHJhbnNhY3Rpb25fZGF0YV9oYXNoZXMiOlsiWHd5VmQ3d0ZSRWRWV0xwbmk1UU5IZ2dOV1hvMko0TG41OHQyX2VjSjczcyJdLCJ0cmFuc2FjdGlvbl9kYXRhX2hhc2hlc19hbGciOiJzaGEtMjU2Iiwic2RfaGFzaCI6IkJFQ09xRm9OMjM0UldtRzEtTUlSWXl5SnpXTDg1XzRLdTdHNC1KcUl4V0UifQ.ZnDZBS8o_WPsTlvuUO0SnARUIvx1M8t9Fd6TiaQbMtT_0OA7QCvdpisSh9-NfLAb40frAED875W8RI3zi06-DQ"}',
          })

          const validatedResult = validateOpenid4vpAuthorizationResponsePayload({
            authorizationRequestPayload,
            authorizationResponsePayload,
          })

          expect(validatedResult).toMatchObject({
            type: 'dcql',
            dcql: {
              query: exampleDcqlQuery,
              presentations: {
                orgeuuniversity:
                  'uQADZ3ZlcnNpb25jMS4waWRvY3VtZW50c4GjZ2RvY1R5cGVxb3JnLmV1LnVuaXZlcnNpdHlsaXNzdWVyU2lnbmVkuQACam5hbWVTcGFjZXOhd2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xg9gYWGGkaGRpZ2VzdElEA3FlbGVtZW50SWRlbnRpZmllcmRuYW1lbGVsZW1lbnRWYWx1ZWhKb2huIERvZWZyYW5kb21YIEWyJGCZTVxZPQlUipZgJrFHAG953ShscUxOhqcVj5zZ2BhYY6RoZGlnZXN0SUQBcWVsZW1lbnRJZGVudGlmaWVyZmRlZ3JlZWxlbGVtZW50VmFsdWVoYmFjaGVsb3JmcmFuZG9tWCAK5tJW8iDu2_pFMZbncXHsVSoMPB-j6NHzTidrmAwglNgYWGakaGRpZ2VzdElEAnFlbGVtZW50SWRlbnRpZmllcmRkYXRlbGVsZW1lbnRWYWx1ZdkD7GoyMDI1LTAyLTI3ZnJhbmRvbVggHkxQ5P0ym4b-S2YhPULns-6950O_pu1f01YH4KZf7RFqaXNzdWVyQXV0aIRDoQEmogRYMXpEbmFlYVpVV3dVUmpyNVE1TTJnMnVjZjE2bjNwVUx4bzRDaHFuZktYTnJNMk53MUsYIYFZAR4wggEaMIHAoAMCAQICEBe3X5XsrOs2ZhTfjDA0whkwCgYIKoZIzj0EAwIwDTELMAkGA1UEAxMCREUwHhcNMjUwMjI3MDkxOTMzWhcNMjYwMjI3MDkxOTMzWjANMQswCQYDVQQDEwJERTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJaBQfh-jpNhVxqwlTlv39Gm3nkewRvcA4p9TRao8YlC271XGo2ojTBcNh-RX65ql--tNygiJh6BHNhz98VPcVCjAjAAMAoGCCqGSM49BAMCA0kAMEYCIQCx9YNNPzp7YPPdy4k3IVR_XLl6e7bnKS91cGEwArbMzgIhAIuglfUtfZM-ZYoEX1xYB47wMm666Trcykjag1sYMfgZWQIA2BhZAfu5AAZndmVyc2lvbmMxLjBvZGlnZXN0QWxnb3JpdGhtZ1NIQS0yNTZsdmFsdWVEaWdlc3RzoXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMaUAWCAVPsuROLqNqsVsaaCrTJzdHdZ_IznS1nCh1qVKWZ2ezQFYIPeazaLvXv5M-s2h9713AG_QJcCZW-eu6UGzoGI6O9ZnAlggqnuFzR9wHj_51ftmjpqo5s-XIvjoLPw-5sfQ-IGtp1kDWCByQ8dnllyBLPNL1DgHqA0B8yAuvY-EoCVGmEAWMAbeowRYICrRJfwVhE9JJzLpa6tfc1LJ9rvv0sr2OzQ9ot-68CnNbWRldmljZUtleUluZm-5AAFpZGV2aWNlS2V5pAECIAEhWCAakKubHmMGh9_OHyUGEZ8102VOMM6j7C-MlEyHDyYJ1yJYIJbQibZhVZZ2ghRAClhsQO_fXpWcqRQKhriSZ4azbE2oZ2RvY1R5cGVxb3JnLmV1LnVuaXZlcnNpdHlsdmFsaWRpdHlJbmZvuQAEZnNpZ25lZMB0MjAyNS0wMi0yN1QwOToxOTozM1ppdmFsaWRGcm9twHQyMDI1LTAyLTI3VDA5OjE5OjMzWmp2YWxpZFVudGlswHQyMDI2LTAyLTI3VDA5OjE5OjMzWm5leHBlY3RlZFVwZGF0ZfdYQCFznxzCxRUqSe65YB3p1pjTEK7Sma4-JTUhnbwsdmtAoLBv5NMlu54mHj7oGCRBmN3G_un8GeX2opmG78yVdJNsZGV2aWNlU2lnbmVkuQACam5hbWVTcGFjZXPYGEGgamRldmljZUF1dGi5AAJvZGV2aWNlU2lnbmF0dXJlhEOhASag9lhA0kcpmpDK-lGZnNZ_cCjb_CbEz6UZ_MwymXE9r1j9YFrSpoahLj6dkprCZuaS1K79dvSZQTHw23KHzP_JAGFcj2lkZXZpY2VNYWP3ZnN0YXR1cwA',
                OpenBadgeCredentialDescriptor:
                  'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSIsImtpZCI6IiN6Nk1rcnpRUEJyNHB5cUM3NzZLS3RyejEzU2NoTTVlUFBic3N1UHVRWmI1dDR1S1EifQ.eyJ2Y3QiOiJPcGVuQmFkZ2VDcmVkZW50aWFsIiwiZGVncmVlIjoiYmFjaGVsb3IiLCJjbmYiOnsia2lkIjoiZGlkOmtleTp6Nk1rcEdSNGdzNFJjM1pwaDR2ajh3Um5qbkF4Z0FQU3hjUjhNQVZLdXRXc3BRemMjejZNa3BHUjRnczRSYzNacGg0dmo4d1Juam5BeGdBUFN4Y1I4TUFWS3V0V3NwUXpjIn0sImlzcyI6ImRpZDprZXk6ejZNa3J6UVBCcjRweXFDNzc2S0t0cnoxM1NjaE01ZVBQYnNzdVB1UVpiNXQ0dUtRIiwiaWF0IjoxNzQwNjQ3OTczLCJfc2QiOlsiSEtyNW1mYkE2OGRZY0JYZTVMRDREdFJHdjVoNWp0NEVDT2JSOWF5VkJCOCIsImlBYS1YVXhGaG1nU0g2SWhTOHZ2cm1TWF95VHJ2ZTQtZjFjTWRPLU41VUUiXSwiX3NkX2FsZyI6InNoYS0yNTYifQ.pP2G3YxexmDGpF-vfb04zMhVLLJGjkiVUiA-I-aLVdhNqzCjexOAu9xQOt0uTGT-4_ly_j66FXR2v4p0z9iyBw~WyI2NTgyNDY2MzM4MjYyODgyMjY2Nzc2MTkiLCJ1bml2ZXJzaXR5IiwiaW5uc2JydWNrIl0~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFZERTQSJ9.eyJpYXQiOjE3NDA2NDc5NzYsIm5vbmNlIjoiNDczODIzNzM5Nzg4MzU1NzEyMTc3MzUwIiwiYXVkIjoieDUwOV9zYW5fZG5zOmxvY2FsaG9zdDoxMjM0IiwidHJhbnNhY3Rpb25fZGF0YV9oYXNoZXMiOlsiWHd5VmQ3d0ZSRWRWV0xwbmk1UU5IZ2dOV1hvMko0TG41OHQyX2VjSjczcyJdLCJ0cmFuc2FjdGlvbl9kYXRhX2hhc2hlc19hbGciOiJzaGEtMjU2Iiwic2RfaGFzaCI6IkJFQ09xRm9OMjM0UldtRzEtTUlSWXl5SnpXTDg1XzRLdTdHNC1KcUl4V0UifQ.ZnDZBS8o_WPsTlvuUO0SnARUIvx1M8t9Fd6TiaQbMtT_0OA7QCvdpisSh9-NfLAb40frAED875W8RI3zi06-DQ',
              },
            },
          })

          return HttpResponse.json({ message: 'completed' })
        } catch (error) {
          console.error(error)
          return HttpResponse.error()
        }
      })
    )

    // verifier
    const authorizationRequest = await createOpenid4vpAuthorizationRequest({
      authorizationRequestPayload,
      callbacks,
    })
    expect(authorizationRequest).toMatchObject({
      authorizationRequestPayload,
      authorizationRequestObject: authorizationRequestPayload,
      authorizationRequest:
        'openid4vp://?response_type=vp_token&client_id=client_id&response_uri=https%3A%2F%2Fexample.com%2Fresponse_uri&response_mode=direct_post&nonce=nonce&dcql_query=%7B%22credentials%22%3A%5B%7B%22id%22%3A%22orgeuuniversity%22%2C%22format%22%3A%22mso_mdoc%22%2C%22meta%22%3A%7B%22doctype_value%22%3A%22org.eu.university%22%7D%2C%22claims%22%3A%5B%7B%22namespace%22%3A%22eu.europa.ec.eudi.pid.1%22%2C%22claim_name%22%3A%22name%22%7D%2C%7B%22namespace%22%3A%22eu.europa.ec.eudi.pid.1%22%2C%22claim_name%22%3A%22degree%22%7D%2C%7B%22namespace%22%3A%22eu.europa.ec.eudi.pid.1%22%2C%22claim_name%22%3A%22date%22%7D%5D%7D%2C%7B%22id%22%3A%22OpenBadgeCredentialDescriptor%22%2C%22format%22%3A%22dc%2Bsd-jwt%22%2C%22meta%22%3A%7B%22vct_values%22%3A%5B%22OpenBadgeCredential%22%5D%7D%2C%22claims%22%3A%5B%7B%22path%22%3A%5B%22university%22%5D%7D%5D%7D%5D%7D&client_metadata=%7B%7D',
      jar: undefined,
    })

    // holder

    const resolved = await resolveOpenid4vpAuthorizationRequest({
      authorizationRequestPayload,
      callbacks,
    })

    expect(resolved).toMatchObject({
      transactionData: undefined,
      authorizationRequestPayload: {
        response_type: 'vp_token',
        client_id: 'client_id',
        response_uri: 'https://example.com/response_uri',
        response_mode: 'direct_post',
        nonce: 'nonce',
        dcql_query: exampleDcqlQuery,
        client_metadata: {},
      },
      jar: undefined,
      client: {
        scheme: 'pre-registered',
        identifier: 'client_id',
        originalValue: 'client_id',
        clientMetadata: {},
      },
      pex: undefined,
      dcql: {
        query: exampleDcqlQuery,
      },
    })

    const response = await createOpenid4vpAuthorizationResponse({
      authorizationRequestPayload,
      authorizationResponsePayload: { vp_token: exampleVptoken },
      callbacks,
    })

    expect(response).toMatchObject({
      authorizationResponsePayload: {
        vp_token: {
          orgeuuniversity:
            'uQADZ3ZlcnNpb25jMS4waWRvY3VtZW50c4GjZ2RvY1R5cGVxb3JnLmV1LnVuaXZlcnNpdHlsaXNzdWVyU2lnbmVkuQACam5hbWVTcGFjZXOhd2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xg9gYWGGkaGRpZ2VzdElEA3FlbGVtZW50SWRlbnRpZmllcmRuYW1lbGVsZW1lbnRWYWx1ZWhKb2huIERvZWZyYW5kb21YIEWyJGCZTVxZPQlUipZgJrFHAG953ShscUxOhqcVj5zZ2BhYY6RoZGlnZXN0SUQBcWVsZW1lbnRJZGVudGlmaWVyZmRlZ3JlZWxlbGVtZW50VmFsdWVoYmFjaGVsb3JmcmFuZG9tWCAK5tJW8iDu2_pFMZbncXHsVSoMPB-j6NHzTidrmAwglNgYWGakaGRpZ2VzdElEAnFlbGVtZW50SWRlbnRpZmllcmRkYXRlbGVsZW1lbnRWYWx1ZdkD7GoyMDI1LTAyLTI3ZnJhbmRvbVggHkxQ5P0ym4b-S2YhPULns-6950O_pu1f01YH4KZf7RFqaXNzdWVyQXV0aIRDoQEmogRYMXpEbmFlYVpVV3dVUmpyNVE1TTJnMnVjZjE2bjNwVUx4bzRDaHFuZktYTnJNMk53MUsYIYFZAR4wggEaMIHAoAMCAQICEBe3X5XsrOs2ZhTfjDA0whkwCgYIKoZIzj0EAwIwDTELMAkGA1UEAxMCREUwHhcNMjUwMjI3MDkxOTMzWhcNMjYwMjI3MDkxOTMzWjANMQswCQYDVQQDEwJERTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJaBQfh-jpNhVxqwlTlv39Gm3nkewRvcA4p9TRao8YlC271XGo2ojTBcNh-RX65ql--tNygiJh6BHNhz98VPcVCjAjAAMAoGCCqGSM49BAMCA0kAMEYCIQCx9YNNPzp7YPPdy4k3IVR_XLl6e7bnKS91cGEwArbMzgIhAIuglfUtfZM-ZYoEX1xYB47wMm666Trcykjag1sYMfgZWQIA2BhZAfu5AAZndmVyc2lvbmMxLjBvZGlnZXN0QWxnb3JpdGhtZ1NIQS0yNTZsdmFsdWVEaWdlc3RzoXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMaUAWCAVPsuROLqNqsVsaaCrTJzdHdZ_IznS1nCh1qVKWZ2ezQFYIPeazaLvXv5M-s2h9713AG_QJcCZW-eu6UGzoGI6O9ZnAlggqnuFzR9wHj_51ftmjpqo5s-XIvjoLPw-5sfQ-IGtp1kDWCByQ8dnllyBLPNL1DgHqA0B8yAuvY-EoCVGmEAWMAbeowRYICrRJfwVhE9JJzLpa6tfc1LJ9rvv0sr2OzQ9ot-68CnNbWRldmljZUtleUluZm-5AAFpZGV2aWNlS2V5pAECIAEhWCAakKubHmMGh9_OHyUGEZ8102VOMM6j7C-MlEyHDyYJ1yJYIJbQibZhVZZ2ghRAClhsQO_fXpWcqRQKhriSZ4azbE2oZ2RvY1R5cGVxb3JnLmV1LnVuaXZlcnNpdHlsdmFsaWRpdHlJbmZvuQAEZnNpZ25lZMB0MjAyNS0wMi0yN1QwOToxOTozM1ppdmFsaWRGcm9twHQyMDI1LTAyLTI3VDA5OjE5OjMzWmp2YWxpZFVudGlswHQyMDI2LTAyLTI3VDA5OjE5OjMzWm5leHBlY3RlZFVwZGF0ZfdYQCFznxzCxRUqSe65YB3p1pjTEK7Sma4-JTUhnbwsdmtAoLBv5NMlu54mHj7oGCRBmN3G_un8GeX2opmG78yVdJNsZGV2aWNlU2lnbmVkuQACam5hbWVTcGFjZXPYGEGgamRldmljZUF1dGi5AAJvZGV2aWNlU2lnbmF0dXJlhEOhASag9lhA0kcpmpDK-lGZnNZ_cCjb_CbEz6UZ_MwymXE9r1j9YFrSpoahLj6dkprCZuaS1K79dvSZQTHw23KHzP_JAGFcj2lkZXZpY2VNYWP3ZnN0YXR1cwA',
          OpenBadgeCredentialDescriptor:
            'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSIsImtpZCI6IiN6Nk1rcnpRUEJyNHB5cUM3NzZLS3RyejEzU2NoTTVlUFBic3N1UHVRWmI1dDR1S1EifQ.eyJ2Y3QiOiJPcGVuQmFkZ2VDcmVkZW50aWFsIiwiZGVncmVlIjoiYmFjaGVsb3IiLCJjbmYiOnsia2lkIjoiZGlkOmtleTp6Nk1rcEdSNGdzNFJjM1pwaDR2ajh3Um5qbkF4Z0FQU3hjUjhNQVZLdXRXc3BRemMjejZNa3BHUjRnczRSYzNacGg0dmo4d1Juam5BeGdBUFN4Y1I4TUFWS3V0V3NwUXpjIn0sImlzcyI6ImRpZDprZXk6ejZNa3J6UVBCcjRweXFDNzc2S0t0cnoxM1NjaE01ZVBQYnNzdVB1UVpiNXQ0dUtRIiwiaWF0IjoxNzQwNjQ3OTczLCJfc2QiOlsiSEtyNW1mYkE2OGRZY0JYZTVMRDREdFJHdjVoNWp0NEVDT2JSOWF5VkJCOCIsImlBYS1YVXhGaG1nU0g2SWhTOHZ2cm1TWF95VHJ2ZTQtZjFjTWRPLU41VUUiXSwiX3NkX2FsZyI6InNoYS0yNTYifQ.pP2G3YxexmDGpF-vfb04zMhVLLJGjkiVUiA-I-aLVdhNqzCjexOAu9xQOt0uTGT-4_ly_j66FXR2v4p0z9iyBw~WyI2NTgyNDY2MzM4MjYyODgyMjY2Nzc2MTkiLCJ1bml2ZXJzaXR5IiwiaW5uc2JydWNrIl0~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFZERTQSJ9.eyJpYXQiOjE3NDA2NDc5NzYsIm5vbmNlIjoiNDczODIzNzM5Nzg4MzU1NzEyMTc3MzUwIiwiYXVkIjoieDUwOV9zYW5fZG5zOmxvY2FsaG9zdDoxMjM0IiwidHJhbnNhY3Rpb25fZGF0YV9oYXNoZXMiOlsiWHd5VmQ3d0ZSRWRWV0xwbmk1UU5IZ2dOV1hvMko0TG41OHQyX2VjSjczcyJdLCJ0cmFuc2FjdGlvbl9kYXRhX2hhc2hlc19hbGciOiJzaGEtMjU2Iiwic2RfaGFzaCI6IkJFQ09xRm9OMjM0UldtRzEtTUlSWXl5SnpXTDg1XzRLdTdHNC1KcUl4V0UifQ.ZnDZBS8o_WPsTlvuUO0SnARUIvx1M8t9Fd6TiaQbMtT_0OA7QCvdpisSh9-NfLAb40frAED875W8RI3zi06-DQ',
        },
      },
    })

    const submissionResult = await submitOpenid4vpAuthorizationResponse({
      authorizationResponsePayload: response.authorizationResponsePayload,
      authorizationRequestPayload,
      callbacks,
    })

    expect(submissionResult.response.status).toBe(200)
  })
})
