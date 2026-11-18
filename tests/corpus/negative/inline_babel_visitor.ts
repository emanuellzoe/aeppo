export const visitor = { Function(path: unknown) { return path } }
export const typed = { Function(path: NodePath): void { path.skip() } }
