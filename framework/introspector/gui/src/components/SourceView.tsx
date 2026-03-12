import { useState, useEffect } from 'react';

type ViewMode = 'definition' | 'callsite';

interface Props {
  definitionUrl: string | null;
  callSiteUrl: string | null;
  functionName: string | null;
  callSiteLabel: string | null;
}

export function SourceView({ definitionUrl, callSiteUrl, functionName, callSiteLabel }: Props) {
  const [mode, setMode] = useState<ViewMode>('callsite');

  useEffect(() => {
    setMode(callSiteUrl ? 'callsite' : 'definition');
  }, [functionName, callSiteUrl]);

  if (!definitionUrl && !callSiteUrl) {
    return (
      <div className="h-full flex items-center justify-center text-zinc-600 text-sm">
        {functionName ? 'No source available (external function)' : 'Select a function to view its source coverage'}
      </div>
    );
  }

  const activeUrl = mode === 'callsite' && callSiteUrl ? callSiteUrl : definitionUrl;

  if (!activeUrl) {
    return (
      <div className="h-full flex flex-col">
        <div className="flex items-center px-2 py-1 bg-zinc-900 border-b border-zinc-800 text-xs gap-1">
          {definitionUrl && (
            <Tab
              active={mode === 'definition'}
              onClick={() => setMode('definition')}
              label="Definition"
              detail={functionName}
            />
          )}
          {callSiteUrl && (
            <Tab
              active={mode === 'callsite'}
              onClick={() => setMode('callsite')}
              label="Call site"
              detail={callSiteLabel}
            />
          )}
        </div>
        <div className="flex-1 flex items-center justify-center text-zinc-600 text-sm">
          No source available for this view
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center px-2 py-1 bg-zinc-900 border-b border-zinc-800 text-xs gap-1">
        {definitionUrl && (
          <Tab
            active={mode === 'definition'}
            onClick={() => setMode('definition')}
            label="Definition"
            detail={functionName}
          />
        )}
        {callSiteUrl && (
          <Tab
            active={mode === 'callsite'}
            onClick={() => setMode('callsite')}
            label="Call site"
            detail={callSiteLabel}
          />
        )}
      </div>
      <iframe
        key={activeUrl}
        src={activeUrl}
        title="Coverage report"
        className="flex-1 w-full border-0 bg-white"
      />
    </div>
  );
}

function Tab({
  active,
  onClick,
  label,
  detail,
}: {
  active: boolean;
  onClick: () => void;
  label: string;
  detail: string | null;
}) {
  return (
    <button
      onClick={onClick}
      className={`cursor-pointer flex items-center gap-1.5 px-2.5 py-1 rounded ${
        active
          ? 'bg-zinc-700 text-zinc-100'
          : 'text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800'
      }`}
    >
      <span className={active ? 'font-medium' : ''}>{label}</span>
      {detail && (
        <span className={`font-mono truncate max-w-48 ${active ? 'text-zinc-400' : 'text-zinc-600'}`}>
          {detail}
        </span>
      )}
    </button>
  );
}
