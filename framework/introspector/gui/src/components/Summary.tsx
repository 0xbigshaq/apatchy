import type { IntrospectData } from '../types';

interface Props {
  data: IntrospectData;
}

function countNodes(node: { children?: { children?: unknown }[] }): number {
  let count = 1;
  for (const child of node.children ?? []) {
    count += countNodes(child as { children?: { children?: unknown }[] });
  }
  return count;
}

function maxDepth(node: { children?: { children?: unknown }[] }, depth = 0): number {
  let max = depth;
  for (const child of node.children ?? []) {
    const d = maxDepth(child as { children?: { children?: unknown }[] }, depth + 1);
    if (d > max) max = d;
  }
  return max;
}

export function Summary({ data }: Props) {
  const funcs = Object.values(data.functions);
  const total = funcs.length;
  const covered = funcs.filter((f) => f.coverage?.hit).length;
  const pct = total > 0 ? ((covered / total) * 100).toFixed(1) : '0';
  const treeNodes = data.call_tree.reduce((sum, root) => sum + countNodes(root), 0);
  const depth = Math.max(...data.call_tree.map((root) => maxDepth(root)), 0);

  return (
    <div className="flex flex-wrap items-center gap-4 px-4 py-3 bg-zinc-900 border-b border-zinc-800 text-sm text-zinc-300">
      <img src="./logo-text.png" alt="Apatchy" className="h-8" />
      <span>
        {data.metadata.entry_points.length === 1 ? 'Entry' : 'Entries'}:{' '}
        <span className="text-white font-mono">{data.metadata.entry_points.join(', ')}</span>
      </span>
      <span className="text-zinc-600">|</span>
      <span>
        Functions: <span className="text-white">{covered}</span>
        <span className="text-zinc-500"> / {total}</span>
        <span className="text-zinc-400"> ({pct}% covered)</span>
      </span>
      <span className="text-zinc-600">|</span>
      <span>
        Tree nodes: <span className="text-white">{treeNodes.toLocaleString()}</span>
      </span>
      <span className="text-zinc-600">|</span>
      <span>
        Max depth: <span className="text-white">{depth}</span>
      </span>
      <span className="text-zinc-600">|</span>
      <span>
        Edges: <span className="text-white">{data.call_edges.length.toLocaleString()}</span>
      </span>
    </div>
  );
}
