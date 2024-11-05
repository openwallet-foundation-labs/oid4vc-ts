export type Simplify<T> = { [KeyType in keyof T]: T[KeyType] } & {}
export type Optional<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>