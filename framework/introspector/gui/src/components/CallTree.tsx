import type { CallTreeNode as CallTreeNodeType, FunctionMeta } from '../types';
import { TreeNode } from './TreeNode';

interface Props {
  roots: CallTreeNodeType[];
  functions: Record<string, FunctionMeta>;
  isExpanded: (key: string, depth: number) => boolean;
  onToggle: (key: string) => void;
  onSelect: (node: CallTreeNodeType, callerName: string | null, nodeKey: string) => void;
  searchQuery: string;
  selectedKey: string | null;
  hideIntrinsics: boolean;
}

export function CallTree({
  roots,
  functions,
  isExpanded,
  onToggle,
  onSelect,
  searchQuery,
  selectedKey,
  hideIntrinsics,
}: Props) {
  return (
    <div className="flex-1 overflow-auto py-1">
      {roots.map((root) => (
        <TreeNode
          key={root.name}
          node={root}
          depth={0}
          nodeKey={root.name}
          callerName={null}
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
