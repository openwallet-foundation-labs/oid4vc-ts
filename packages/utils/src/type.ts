export type Simplify<T> = { [KeyType in keyof T]: T[KeyType] } & {}
export type Optional<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>
export type StringWithAutoCompletion<T extends string> = T | (string & {})
export type OrPromise<T> = T | Promise<T>
export type NonEmptyArray<T> = [T, ...T[]]
