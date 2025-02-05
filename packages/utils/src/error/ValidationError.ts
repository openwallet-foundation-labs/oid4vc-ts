import type z from 'zod'
import { type ZodError, type ZodIssue, ZodIssueCode } from 'zod'

/**
 * Some code comes from `zod-validation-error` package (MIT License) and
 * was slightly simplified to fit our needs.
 */
const constants = {
  // biome-ignore lint/suspicious/noMisleadingCharacterClass: expected
  identifierRegex: /[$_\p{ID_Start}][$\u200c\u200d\p{ID_Continue}]*/u,
  unionSeparator: ', or ',
  issueSeparator: '\n\t- ',
}

export class ValidationError extends Error {
  public zodError: ZodError | undefined

  private escapeQuotes(str: string): string {
    return str.replace(/"/g, '\\"')
  }

  private joinPath(path: Array<string | number>): string {
    if (path.length === 1) {
      return path[0].toString()
    }

    return path.reduce<string>((acc, item) => {
      // handle numeric indices
      if (typeof item === 'number') {
        return `${acc}[${item.toString()}]`
      }

      // handle quoted values
      if (item.includes('"')) {
        return `${acc}["${this.escapeQuotes(item)}"]`
      }

      // handle special characters
      if (!constants.identifierRegex.test(item)) {
        return `${acc}["${item}"]`
      }

      // handle normal values
      const separator = acc.length === 0 ? '' : '.'
      return acc + separator + item
    }, '')
  }

  private getMessageFromUnionErrors(unionErrors: z.ZodError[]): string {
    return unionErrors
      .reduce<string[]>((acc, zodError) => {
        const newIssues = zodError.issues
          .map((issue) => this.getMessageFromZodIssue(issue))
          .join(constants.issueSeparator)

        if (!acc.includes(newIssues)) acc.push(newIssues)

        return acc
      }, [])
      .join(constants.unionSeparator)
  }

  private getMessageFromZodIssue(issue: ZodIssue): string {
    if (issue.code === ZodIssueCode.invalid_union) {
      return this.getMessageFromUnionErrors(issue.unionErrors)
    }

    if (issue.code === ZodIssueCode.invalid_arguments) {
      return [issue.message, ...issue.argumentsError.issues.map((issue) => this.getMessageFromZodIssue(issue))].join(
        constants.issueSeparator
      )
    }

    if (issue.code === ZodIssueCode.invalid_return_type) {
      return [issue.message, ...issue.returnTypeError.issues.map((issue) => this.getMessageFromZodIssue(issue))].join(
        constants.issueSeparator
      )
    }

    if (issue.path.length !== 0) {
      // handle array indices
      if (issue.path.length === 1) {
        const identifier = issue.path[0]

        if (typeof identifier === 'number') {
          return `${issue.message} at index ${identifier}`
        }
      }

      return `${issue.message} at "${this.joinPath(issue.path)}"`
    }

    return issue.message
  }

  private formatError(error?: z.ZodError): string {
    if (!error) return ''

    return error?.issues.map((issue) => this.getMessageFromZodIssue(issue)).join(constants.issueSeparator)
  }

  constructor(message: string, zodError?: z.ZodError) {
    super(message)

    const formattedError = this.formatError(zodError)
    this.message = `${message}\n\t- ${formattedError}`

    Object.defineProperty(this, 'zodError', {
      value: zodError,
      writable: false,
      enumerable: false,
    })
  }
}
