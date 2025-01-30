import z from 'zod'

const vNotificationEvent = z.enum(['credential_accepted', 'credential_failure', 'credential_deleted'])
export type NotificationEvent = z.infer<typeof vNotificationEvent>

export const vNotificationRequest = z
  .object({
    notification_id: z.string(),
    event: vNotificationEvent,
    event_description: z.optional(z.string()),
  })
  .passthrough()

export type NotificationRequest = z.infer<typeof vNotificationRequest>

export const vNotificationErrorResponse = z
  .object({
    error: z.enum(['invalid_notification_id', 'invalid_notification_request']),
  })
  .passthrough()
export type NotificationErrorResponse = z.infer<typeof vNotificationErrorResponse>
