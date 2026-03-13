import type { CallTreeNode, FunctionMeta } from '../types';

interface Props {
  node: CallTreeNode;
  depth: number;
  nodeKey: string;
  callerName: string | null;
  functions: Record<string, FunctionMeta>;
  isExpanded: (key: string, depth: number) => boolean;
  onToggle: (key: string) => void;
  onSelect: (node: CallTreeNode, callerName: string | null, nodeKey: string) => void;
  searchQuery: string;
  selectedKey: string | null;
  hideIntrinsics: boolean;
}

export function TreeNode({
  node,
  depth,
  nodeKey,
  callerName,
  functions,
  isExpanded,
  onToggle,
  onSelect,
  searchQuery,
  selectedKey,
  hideIntrinsics,
}: Props) {
  const expanded = isExpanded(nodeKey, depth);
  const func = functions[node.name];
  const isExternal = !func || !func.source_file;
  const isHit = func?.coverage?.hit ?? false;
  const hasChildren = node.children && node.children.length > 0;
  const isSelected = nodeKey === selectedKey;

  const matchesSearch =
    searchQuery && node.name.toLowerCase().includes(searchQuery.toLowerCase());

  const isHidden =
    searchQuery && !matchesSearch && !hasMatchingDescendant(node, searchQuery);

  if (isHidden) return null;
  if (hideIntrinsics && node.name.startsWith('llvm.lifetime.')) return null;

  const hasSiteCount = node.site_count !== undefined && node.site_count !== -1;
  const siteHit = node.site_count > 0;

  const colorDot = hasSiteCount
    ? siteHit
      ? 'bg-green-500'
      : 'bg-red-500'
    : isHit
      ? 'bg-green-500'
      : 'bg-red-500';

  const textColor = matchesSearch
    ? 'text-yellow-200'
    : isSelected
      ? 'text-white'
      : isExternal
        ? 'text-zinc-500'
        : isHit
          ? 'text-zinc-300'
          : 'text-zinc-400';

  const bgClass = matchesSearch
    ? 'bg-yellow-500/15'
    : isSelected
      ? 'bg-zinc-700/60'
      : 'hover:bg-zinc-800/50';

  return (
    <div>
      <div
        className={`flex items-center h-6 cursor-pointer select-none ${bgClass}`}
        style={{ paddingLeft: depth * 16 + 4 }}
        onClick={() => onSelect(node, callerName, nodeKey)}
      >
        {hasChildren ? (
          <button
            onClick={(e) => {
              e.stopPropagation();
              onToggle(nodeKey);
            }}
            className="w-4 h-4 flex items-center justify-center text-zinc-500 hover:text-zinc-300 flex-shrink-0 cursor-pointer"
          >
            <svg
              className={`w-3 h-3 transition-transform ${expanded ? 'rotate-90' : ''}`}
              viewBox="0 0 16 16"
              fill="currentColor"
            >
              <path d="M6 4l4 4-4 4z" />
            </svg>
          </button>
        ) : (
          <span className="w-4 flex-shrink-0" />
        )}

        <span className={`w-2 h-2 rounded-full ${colorDot} flex-shrink-0 mx-1.5`} />

        <span className={`text-xs font-mono truncate ${textColor}`}>
          {node.name}
        </span>

        {hasChildren && (
          <span className="text-zinc-600 text-xs ml-1 flex-shrink-0">
            {node.children.length}
          </span>
        )}

        {isExternal && (
          <span className="text-zinc-700 text-xs ml-1 flex-shrink-0 italic">
            ext
          </span>
        )}
      </div>

      {expanded &&
        hasChildren &&
        node.children.map((child, i) => (
          <TreeNode
            key={`${child.name}-${i}`}
            node={child}
            depth={depth + 1}
            nodeKey={`${nodeKey}/${child.name}-${i}`}
            callerName={node.name}
            functions={functions}
            isExpanded={isExpanded}
            onToggle={onToggle}
            onSelect={onSelect}
            searchQuery={searchQuery}
            selectedKey={selectedKey}
            hideIntrinsics={hideIntrinsics}
          />
        ))}
    </div>
  );
}

function hasMatchingDescendant(node: CallTreeNode, query: string): boolean {
  const lower = query.toLowerCase();
  for (const child of node.children ?? []) {
    if (child.name.toLowerCase().includes(lower)) return true;
    if (hasMatchingDescendant(child, query)) return true;
  }
  return false;
}
