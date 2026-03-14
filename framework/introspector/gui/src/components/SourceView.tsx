import { useCallback, useEffect, useRef, useState } from 'react';

type ViewMode = 'definition' | 'callsite' | 'index';

type CovLine = 'hit' | 'miss' | 'none';

interface Props {
  definitionUrl: string | null;
  callSiteUrl: string | null;
  functionName: string | null;
  callSiteLabel: string | null;
  reportBaseUrl: string;
  overrideUrl?: string | null;
  onNavigate?: (url: string) => void;
}

export function SourceView({ definitionUrl, callSiteUrl, functionName, callSiteLabel, reportBaseUrl, overrideUrl, onNavigate }: Props) {
  const [mode, setMode] = useState<ViewMode>('callsite');
  const [covLines, setCovLines] = useState<CovLine[]>([]);
  const [scrollRatio, setScrollRatio] = useState(0);
  const iframeRef = useRef<HTMLIFrameElement>(null);
  const indexUrl = `${reportBaseUrl}/index.html`;

  useEffect(() => {
    setMode(callSiteUrl ? 'callsite' : 'definition');
  }, [functionName, callSiteUrl]);

  const activeUrl = overrideUrl
    ? overrideUrl
    : mode === 'index' ? indexUrl
      : mode === 'callsite' && callSiteUrl ? callSiteUrl
        : definitionUrl ?? indexUrl;

  const handleIframeLoad = useCallback((e: React.SyntheticEvent<HTMLIFrameElement>) => {
    const iframe = e.currentTarget;
    try {
      const doc = iframe.contentDocument;
      if (!doc) return;

      const iframeUrl = iframe.contentWindow?.location.href;
      if (iframeUrl && onNavigate) {
        onNavigate(iframeUrl);
      }

      // scroll to hash
      const hash = new URL(iframe.src, location.href).hash;
      if (hash) {
        const target = doc.querySelector(hash) || doc.querySelector(`a[name="${hash.slice(1)}"]`);
        if (target) {
          target.scrollIntoView({ block: 'center' });
        }
      }

      // extract coverage line data for the nav band
      const rows = doc.querySelectorAll('tr');
      const lines: CovLine[] = [];
      rows.forEach((row) => {
        const countCell = row.querySelector('td.covered-line, td.uncovered-line');
        if (!countCell) {
          lines.push('none');
          return;
        }
        if (countCell.classList.contains('covered-line')) {
          lines.push('hit');
        } else if (countCell.classList.contains('uncovered-line')) {
          const text = (countCell.textContent || '').trim();
          lines.push(text === '0' ? 'miss' : 'none');
        } else {
          lines.push('none');
        }
      });
      setCovLines(lines);

      const allRows = Array.from(rows);
      const onScroll = () => {
        const el = doc.scrollingElement || doc.documentElement;
        const viewportCenter = el.scrollTop + el.clientHeight / 2;
        let centerIdx = 0;
        for (let i = 0; i < allRows.length; i++) {
          const r = allRows[i] as HTMLElement;
          if (r.offsetTop + r.offsetHeight / 2 >= viewportCenter) {
            centerIdx = i;
            break;
          }
          centerIdx = i;
        }
        setScrollRatio(allRows.length > 1 ? centerIdx / (allRows.length - 1) : 0);
      };
      doc.addEventListener('scroll', onScroll);
      onScroll();

      const win = iframe.contentWindow;
      const onHashChange = () => {
        if (win && onNavigate) {
          onNavigate(win.location.href);
        }
      };
      win?.addEventListener('hashchange', onHashChange);

      (iframe as any).__cleanupScroll = () => {
        doc.removeEventListener('scroll', onScroll);
        win?.removeEventListener('hashchange', onHashChange);
      };
    } catch { /* cross-origin, ignore */ }
  }, [onNavigate]);

  const handleBandClick = useCallback((ratio: number) => {
    try {
      const doc = iframeRef.current?.contentDocument;
      if (!doc) return;
      const rows = doc.querySelectorAll('tr');
      const idx = Math.floor(ratio * rows.length);
      const target = rows[Math.min(idx, rows.length - 1)];
      if (target) target.scrollIntoView({ block: 'center' });
    } catch { /* cross-origin */ }
  }, []);

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
      {covLines.length > 0 && <NavBand lines={covLines} scrollRatio={scrollRatio} onClick={handleBandClick} />}
      <iframe
        ref={iframeRef}
        key={activeUrl}
        src={activeUrl}
        title="Coverage report"
        className="flex-1 w-full border-0"
        onLoad={handleIframeLoad}
      />
    </div>
  );
}

function NavBand({ lines, scrollRatio, onClick }: { lines: CovLine[]; scrollRatio: number; onClick: (ratio: number) => void }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const width = canvas.offsetWidth;
    const height = 6;
    canvas.width = width;
    canvas.height = height;

    const total = lines.length;
    if (total === 0) return;

    for (let x = 0; x < width; x++) {
      const lineIdx = Math.floor((x / width) * total);
      const line = lines[lineIdx];
      if (line === 'hit') {
        ctx.fillStyle = '#22c55e';
      } else if (line === 'miss') {
        ctx.fillStyle = '#ef4444';
      } else {
        ctx.fillStyle = '#3f3f46';
      }
      ctx.fillRect(x, 0, 1, height);
    }
  }, [lines]);

  return (
    <div className="relative flex-shrink-0">
      <div
        className="absolute text-zinc-400 text-[8px] leading-none select-none pointer-events-none"
        style={{ left: `${scrollRatio * 100}%`, top: 0, transform: 'translateX(-50%)' }}
      >
        v
      </div>
      <canvas
        ref={canvasRef}
        className="w-full cursor-pointer"
        style={{ height: 18, marginTop: 10 }}
        onClick={(e) => {
          const rect = e.currentTarget.getBoundingClientRect();
          const ratio = (e.clientX - rect.left) / rect.width;
          onClick(ratio);
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
