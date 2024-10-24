import * as v from 'valibot'
import type { RequestDpopOptions } from '../authorization/dpop/dpop'
import { resourceRequestWithDpopRetry } from '../authorization/resource-request'
import type { CallbackContext } from '../callbacks'
import { ContentType } from '../common/content-type'
import { parseWithErrorHandling } from '../common/validation/parse'
import { Oid4vcError } from '../error/Oid4vcError'
import { Oid4vcInvalidFetchResponseError } from '../error/Oid4vcInvalidFetchResponseError'
import { Oid4vcOauthErrorResponseError } from '../error/Oid4vcOauthErrorResponseError'
import type { IssuerMetadataResult } from '../metadata/fetch-issuer-metadata'
import { defaultFetcher } from '../utils/valibot-fetcher'
import {
  type NotificationEvent,
  type NotificationRequest,
  vNotificationErrorResponse,
  vNotificationRequest,
} from './v-notification'

export interface SendNotifcationOptions {
  notification: {
    /**
     * Notification id, as returned in the credential response
     */
    notificationId: string

    /**
     * The notification
     */
    event: NotificationEvent

    /**
     * Humand readable desription of the event
     */
    eventDescription?: string
  }

  /**
   * Metadata of the credential issuer and authorization servers.
   */
  issuerMetadata: IssuerMetadataResult

  /**
   * Callback used in notification endpoint
   */
  callbacks: Pick<CallbackContext, 'fetch' | 'generateRandom' | 'hash' | 'signJwt'>

  /**
   * Access token authorized to retrieve the credential(s)
   */
  accessToken: string

  /**
   * DPoP options
   */
  dpop?: RequestDpopOptions

  /**
   * Additional payload to include in the notification request.
   */
  additionalRequestPayload?: Record<string, unknown>
}

export async function sendNotifcation(options: SendNotifcationOptions) {
  const fetcher = options.callbacks.fetch ?? defaultFetcher
  const notificationEndpoint = options.issuerMetadata.credentialIssuer.notification_endpoint

  if (!notificationEndpoint) {
    throw new Oid4vcError(
      `Credential issuer '${options.issuerMetadata.credentialIssuer.credential_issuer}' does not have a notification endpiont configured.`
    )
  }

  const notificationRequest = parseWithErrorHandling(
    vNotificationRequest,
    {
      event: options.notification.event,
      notification_id: options.notification.notificationId,
      event_description: options.notification.eventDescription,
    } satisfies NotificationRequest,
    'Error validating notification request'
  )

  const { dpop } = await resourceRequestWithDpopRetry({
    dpop: options.dpop
      ? {
          ...options.dpop,
          httpMethod: 'POST',
          requestUri: notificationEndpoint,
        }
      : undefined,
    accessToken: options.accessToken,
    callbacks: options.callbacks,
    resourceRequest: async ({ headers }) => {
      const response = await fetcher(notificationEndpoint, {
        body: JSON.stringify(notificationRequest),
        method: 'POST',
        headers: {
          ...headers,
          'Content-Type': ContentType.Json,
        },
      })

      if (!response.ok) {
        const notificationErrorResponse = v.safeParse(
          vNotificationErrorResponse,
          await response
            .clone()
            .json()
            .catch(() => null)
        )
        if (notificationErrorResponse.success) {
          throw new Oid4vcOauthErrorResponseError(
            `Unable to send notification to '${notificationEndpoint}'. Received response with status ${response.status}`,
            notificationErrorResponse.output,
            response
          )
        }

        throw new Oid4vcInvalidFetchResponseError(
          `Unable to send notification to '${notificationEndpoint}'. Received response with status ${response.status}`,
          await response.clone().text(),
          response
        )
      }

      return {
        result: undefined,
        response,
      }
    },
  })

  return { dpop }
}
