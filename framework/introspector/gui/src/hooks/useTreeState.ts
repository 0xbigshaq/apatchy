import { useCallback, useState } from 'react';

export function useTreeState(autoExpandDepth = 2) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [globalOverride, setGlobalOverride] = useState<boolean | null>(null);

  const isExpanded = useCallback(
    (nodeKey: string, depth: number) => {
      if (nodeKey in expanded) return expanded[nodeKey];
      if (globalOverride !== null) return globalOverride;
      return depth < autoExpandDepth;
    },
    [expanded, globalOverride, autoExpandDepth],
  );

  const toggle = useCallback((nodeKey: string) => {
    setExpanded((prev) => {
      const wasExpanded =
        nodeKey in prev ? prev[nodeKey] : globalOverride ?? false;
      return { ...prev, [nodeKey]: !wasExpanded };
    });
  }, [globalOverride]);

  const expandAll = useCallback(() => {
    setExpanded({});
    setGlobalOverride(true);
  }, []);

  const collapseAll = useCallback(() => {
    setExpanded({});
    setGlobalOverride(false);
  }, []);

  return { isExpanded, toggle, expandAll, collapseAll };
}
