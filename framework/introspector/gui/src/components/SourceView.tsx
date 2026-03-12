import { useEffect, useState } from 'react';

type ViewMode = 'definition' | 'callsite' | 'index';

interface Props {
  definitionUrl: string | null;
  callSiteUrl: string | null;
  functionName: string | null;
  callSiteLabel: string | null;
  reportBaseUrl: string;
  overrideUrl?: string | null;
}

export function SourceView({ definitionUrl, callSiteUrl, functionName, callSiteLabel, reportBaseUrl, overrideUrl }: Props) {
  const [mode, setMode] = useState<ViewMode>('callsite');
  const indexUrl = `${reportBaseUrl}/index.html`;

  useEffect(() => {
    setMode(callSiteUrl ? 'callsite' : 'definition');
  }, [functionName, callSiteUrl]);

  const activeUrl = overrideUrl
    ? overrideUrl
    : mode === 'index' ? indexUrl
      : mode === 'callsite' && callSiteUrl ? callSiteUrl
        : definitionUrl ?? indexUrl;

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center px-2 py-1 bg-zinc-900 border-b border-zinc-800 text-xs gap-1">
        <Tab
          active={mode === 'index'}
          onClick={() => setMode('index')}
          label="Summary"
          detail={null}
        />
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
        className="flex-1 w-full border-0"
        onLoad={(e) => {
          const iframe = e.currentTarget;
          try {
            const doc = iframe.contentDocument;
            if (!doc) return;
            const hash = new URL(iframe.src, location.href).hash;
            if (!hash) return;
            const target = doc.querySelector(hash) || doc.querySelector(`a[name="${hash.slice(1)}"]`);
            if (target) {
              target.scrollIntoView({ block: 'center' });
            }
          } catch { /* cross-origin, ignore */ }
        }}
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
      className={`cursor-pointer flex items-center gap-1.5 px-2.5 py-1 rounded ${active
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
