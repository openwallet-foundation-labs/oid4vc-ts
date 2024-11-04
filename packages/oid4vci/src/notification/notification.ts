import * as v from 'valibot'

import {
  type CallbackContext,
  ContentType,
  Oauth2ClientErrorResponseError,
  Oauth2Error,
  Oauth2InvalidFetchResponseError,
  type RequestDpopOptions,
  resourceRequestWithDpopRetry,
} from '@animo-id/oauth2'
import { defaultFetcher, parseWithErrorHandling } from '@animo-id/oauth2-utils'
import type { IssuerMetadataResult } from '../metadata/fetch-issuer-metadata'
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
    throw new Oauth2Error(
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
          request: {
            method: 'POST',
            url: notificationEndpoint,
          },
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
          throw new Oauth2ClientErrorResponseError(
            `Unable to send notification to '${notificationEndpoint}'. Received response with status ${response.status}`,
            notificationErrorResponse.output,
            response
          )
        }

        throw new Oauth2InvalidFetchResponseError(
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
