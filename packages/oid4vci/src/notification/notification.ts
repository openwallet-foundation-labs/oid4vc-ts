import {
  type CallbackContext,
  Oauth2Error,
  type RequestDpopOptions,
  type ResourceRequestResponseNotOk,
  type ResourceRequestResponseOk,
  resourceRequest,
} from '@openid4vc/oauth2'
import { ContentType, isResponseContentType, parseWithErrorHandling } from '@openid4vc/utils'
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

export type SendNotificationResponseOk = ResourceRequestResponseOk
export interface SendNotificationResponseNotOk extends ResourceRequestResponseNotOk {
  /**
   * If this is defined it means the response was JSON and we tried to parse it as
   * a notification error response. It may be successfull or it may not be.
   */
  notificationErrorResponseResult?: ReturnType<typeof vNotificationErrorResponse.safeParse>
}

export async function sendNotifcation(
  options: SendNotifcationOptions
): Promise<SendNotificationResponseNotOk | SendNotificationResponseOk> {
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

  const resourceResponse = await resourceRequest({
    dpop: options.dpop,
    accessToken: options.accessToken,
    callbacks: options.callbacks,
    url: notificationEndpoint,
    requestOptions: {
      method: 'POST',
      headers: {
        'Content-Type': ContentType.Json,
      },
      body: JSON.stringify(notificationRequest),
    },
  })

  if (!resourceResponse.ok) {
    const notificationErrorResponseResult = isResponseContentType(ContentType.Json, resourceResponse.response)
      ? vNotificationErrorResponse.safeParse(await resourceResponse.response.clone().json())
      : undefined

    return {
      ...resourceResponse,
      notificationErrorResponseResult,
    }
  }

  return resourceResponse
}
