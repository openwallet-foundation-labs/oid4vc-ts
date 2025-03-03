import { z } from 'zod'

export const zPexPresentationDefinition = z.record(z.any())
export const zPexPresentationSubmission = z.record(z.any())

export type PexPresentationDefinition = z.infer<typeof zPexPresentationDefinition>
export type PexPresentationSubmission = z.infer<typeof zPexPresentationSubmission>
