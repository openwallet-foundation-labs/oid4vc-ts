import * as v from 'valibot'

const vNotificationEvent = v.picklist(['credential_accepted', 'credential_failure', 'credential_deleted'])
export type NotificationEvent = v.InferOutput<typeof vNotificationEvent>

export const vNotificationRequest = v.looseObject({
  notification_id: v.string(),
  event: vNotificationEvent,
  event_description: v.optional(v.string()),
})
export type NotificationRequest = v.InferOutput<typeof vNotificationRequest>

export const vNotificationErrorResponse = v.looseObject({
  error: v.picklist(['invalid_notification_id', 'invalid_notification_request']),
})
export type NotificationErrorResponse = v.InferOutput<typeof vNotificationErrorResponse>
