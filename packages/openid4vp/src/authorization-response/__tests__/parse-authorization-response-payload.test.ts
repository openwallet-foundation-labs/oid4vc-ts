import { describe, expect, test } from 'vitest'
import { parseOpenid4VpAuthorizationResponsePayload } from '../parse-authorization-response-payload'

describe('parseOpenid4VpAuthorizationResponsePayload', () => {
  test('should correctly handle stringified arguments due to response submitted as query', () => {
    const parsedPayload = Object.fromEntries(
      new URLSearchParams(
        'expires_in=6000&state=126781532216424167140483&presentation_submission=%7B%22id%22%3A%22-tM_1SXzc0Q5hJrTkb4vV%22%2C%22definition_id%22%3A%22307d67e7-e41b-416a-99da-334858b346b7%22%2C%22descriptor_map%22%3A%5B%7B%22id%22%3A%227379f4ed-4781-455f-b33d-d29f6c90cda2%22%2C%22format%22%3A%22vc%2Bsd-jwt%22%2C%22path%22%3A%22%24%22%7D%5D%7D&vp_token=vptoken'
      ).entries()
    )

    expect(parseOpenid4VpAuthorizationResponsePayload(parsedPayload)).toEqual({
      expires_in: 6000,
      state: '126781532216424167140483',
      vp_token: 'vptoken',
      presentation_submission: {
        id: '-tM_1SXzc0Q5hJrTkb4vV',
        definition_id: '307d67e7-e41b-416a-99da-334858b346b7',
        descriptor_map: [
          {
            id: '7379f4ed-4781-455f-b33d-d29f6c90cda2',
            format: 'vc+sd-jwt',
            path: '$',
          },
        ],
      },
    })
  })
})
