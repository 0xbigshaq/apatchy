export function coverageUrl(
  sourceDir: string,
  sourceFile: string,
  line: number,
  reportBaseUrl: string
): string | null {
  if (!sourceDir || !sourceFile) return null;
  const dir = sourceDir.replace(/^\//, '');
  return `${reportBaseUrl}/coverage/${dir}/${sourceFile}.html#L${line}`;
}
