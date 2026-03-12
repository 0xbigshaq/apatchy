import { useCallback, useState } from 'react';

export function useTreeState(autoExpandDepth = 2) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  const isExpanded = useCallback(
    (nodeKey: string, depth: number) => {
      if (nodeKey in expanded) return expanded[nodeKey];
      return depth < autoExpandDepth;
    },
    [expanded, autoExpandDepth],
  );

  const toggle = useCallback((nodeKey: string) => {
    setExpanded((prev) => ({ ...prev, [nodeKey]: !prev[nodeKey] }));
  }, []);

  const expandAll = useCallback(() => {
    setExpanded((prev) => {
      const next = { ...prev };
      for (const key of Object.keys(next)) next[key] = true;
      return next;
    });
  }, []);

  const collapseAll = useCallback(() => {
    setExpanded((prev) => {
      const next = { ...prev };
      for (const key of Object.keys(next)) next[key] = false;
      return next;
    });
  }, []);

  return { isExpanded, toggle, expandAll, collapseAll };
}
