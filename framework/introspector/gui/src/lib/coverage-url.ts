export function coverageUrl(
  sourceDir: string,
  sourceFile: string,
  line: number,
  reportBaseUrl: string,
  sourceRoot?: string
): string | null {
  if (!sourceDir || !sourceFile) return null;
  let dir = sourceDir;
  if (sourceRoot && dir.startsWith(sourceRoot)) {
    dir = dir.slice(sourceRoot.length);
  }
  dir = dir.replace(/^\//, '');
  return `${reportBaseUrl}/coverage/${dir}/${sourceFile}.html#L${line}`;
}
