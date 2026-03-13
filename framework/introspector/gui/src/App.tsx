import { useMemo, useState } from 'react';
import { Panel, PanelGroup, PanelResizeHandle } from 'react-resizable-panels';
import { CallTree } from './components/CallTree';
import { CoveragePanel } from './components/CoveragePanel';
import { SearchBar } from './components/SearchBar';
import { SourceView } from './components/SourceView';
import { Summary } from './components/Summary';
import { useIntrospectData } from './hooks/useIntrospectData';
import { useTreeState } from './hooks/useTreeState';
import type { CallTreeNode } from './types';

const REPORT_BASE_URL = './coverage-report/html';

function App() {
  const { data, error, loading } = useIntrospectData();
  const { isExpanded, toggle, expandAll, collapseAll } = useTreeState(2);
  const [searchQuery, setSearchQuery] = useState('');
  const [selection, setSelection] = useState<{
    node: CallTreeNode;
    callerName: string | null;
    nodeKey: string;
  } | null>(null);
  const [panelOverrideUrl, setPanelOverrideUrl] = useState<string | null>(null);
  const [hideIntrinsics, setHideIntrinsics] = useState(true);

  const matchCount = useMemo(() => {
    if (!data || !searchQuery) return 0;
    const lower = searchQuery.toLowerCase();
    return Object.keys(data.functions).filter((name) =>
      name.toLowerCase().includes(lower),
    ).length;
  }, [data, searchQuery]);

  const selectedFunc = selection ? data?.functions[selection.node.name] : undefined;

  const fileFunctions = useMemo(() => {
    if (!selectedFunc || !data) return [];
    const file = selectedFunc.source_file;
    const dir = selectedFunc.source_dir;
    return Object.entries(data.functions)
      .filter(([, f]) => f.source_file === file && f.source_dir === dir)
      .map(([name, f]) => ({ name, ...f }))
      .sort((a, b) => a.line_start - b.line_start);
  }, [selectedFunc, data]);

  const definitionUrl = useMemo(() => {
    if (!selectedFunc) return null;
    const { source_dir, source_file, line_start } = selectedFunc;
    if (!source_dir || !source_file) return null;
    const dir = source_dir.replace(/^\//, '');
    return `${REPORT_BASE_URL}/coverage/${dir}/${source_file}.html#L${line_start}`;
  }, [selectedFunc]);

  const callSiteUrl = useMemo(() => {
    if (!selection?.node.site_file || !selection.callerName) return null;
    const callerFunc = data?.functions[selection.callerName];
    if (!callerFunc?.source_dir) return null;
    const dir = callerFunc.source_dir.replace(/^\//, '');
    return `${REPORT_BASE_URL}/coverage/${dir}/${selection.node.site_file}.html#L${selection.node.site_line}`;
  }, [selection, data]);

  if (loading) {
    return (
      <div className="h-screen bg-zinc-950 flex items-center justify-center text-zinc-500">
        Loading introspect.json...
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="h-screen bg-zinc-950 flex items-center justify-center text-red-400">
        {error ?? 'Failed to load data'}
      </div>
    );
  }

  return (
    <div className="h-screen bg-zinc-950 text-zinc-200 flex flex-col overflow-hidden">
      <Summary data={data} />

      <PanelGroup direction="horizontal" className="flex-1">
        {/* Left sidebar - call tree */}
        <Panel defaultSize={20} minSize={12} maxSize={35} id="sidebar">
          <div className="flex flex-col h-full bg-zinc-900">
            <SearchBar query={searchQuery} onChange={setSearchQuery} matchCount={matchCount} />
            <div className="flex items-center gap-2 px-3 py-1 border-b border-zinc-800">
              <button
                onClick={expandAll}
                className="text-xs text-zinc-500 hover:text-zinc-300 cursor-pointer"
              >
                expand all
              </button>
              <button
                onClick={collapseAll}
                className="text-xs text-zinc-500 hover:text-zinc-300 cursor-pointer"
              >
                collapse all
              </button>
              <label className="flex items-center gap-1 ml-auto cursor-pointer">
                <input
                  type="checkbox"
                  checked={hideIntrinsics}
                  onChange={(e) => setHideIntrinsics(e.target.checked)}
                  className="accent-zinc-500 w-3 h-3"
                />
                <span className="text-xs text-zinc-500">hide llvm.*</span>
              </label>
            </div>
            <CallTree
              root={data.call_tree}
              functions={data.functions}
              isExpanded={isExpanded}
              onToggle={toggle}
              onSelect={(node, callerName, nodeKey) => { setSelection({ node, callerName, nodeKey }); setPanelOverrideUrl(null); }}
              searchQuery={searchQuery}
              selectedKey={selection?.nodeKey ?? null}
              hideIntrinsics={hideIntrinsics}
            />
          </div>
        </Panel>

        <PanelResizeHandle className="w-1 bg-zinc-800 hover:bg-zinc-600 transition-colors" />

        {/* Center + bottom area */}
        <Panel defaultSize={80} id="main">
          <PanelGroup direction="vertical">
            {/* Center - source viewer */}
            <Panel defaultSize={70} minSize={30} id="source">
              <SourceView
                definitionUrl={definitionUrl}
                callSiteUrl={callSiteUrl}
                functionName={selection?.node.name ?? null}
                callSiteLabel={
                  selection?.node.site_file
                    ? `${selection.node.site_file}:${selection.node.site_line}`
                    : null
                }
                reportBaseUrl={REPORT_BASE_URL}
                overrideUrl={panelOverrideUrl}
              />
            </Panel>

            <PanelResizeHandle className="h-1 bg-zinc-800 hover:bg-zinc-600 transition-colors" />

            {/* Bottom - coverage panel */}
            <Panel defaultSize={30} minSize={10} maxSize={50} id="coverage">
              {selection ? (
                <CoveragePanel
                  functions={fileFunctions}
                  selectedName={selection.node.name}
                  reportBaseUrl={REPORT_BASE_URL}
                  onFunctionClick={(f) => {
                    if (!f.source_dir || !f.source_file) return;
                    const dir = f.source_dir.replace(/^\//, '');
                    setPanelOverrideUrl(`${REPORT_BASE_URL}/coverage/${dir}/${f.source_file}.html#L${f.line_start}`);
                  }}
                />
              ) : (
                <div className="h-full bg-zinc-900 border-t border-zinc-800" />
              )}
            </Panel>
          </PanelGroup>
        </Panel>
      </PanelGroup>
    </div>
  );
}

export default App;
