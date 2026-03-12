import { coverageUrl } from '../lib/coverage-url';
import type { FunctionMeta } from '../types';

type FunctionRow = FunctionMeta & { name: string };

interface Props {
  functions: FunctionRow[];
  selectedName: string;
  reportBaseUrl: string;
  onFunctionClick?: (func: FunctionRow) => void;
}

export function CoveragePanel({ functions, selectedName, reportBaseUrl, onFunctionClick }: Props) {
  if (functions.length === 0) {
    return (
      <div className="h-full flex items-center justify-center text-zinc-600 text-sm">
        No coverage data for this function
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col bg-zinc-900 border-t border-zinc-800">
      <div className="flex items-center px-3 py-1.5 border-b border-zinc-800 text-xs flex-shrink-0">
        <span className="text-zinc-500">Coverage</span>
        <span className="text-zinc-600 mx-2">|</span>
        <span className="text-zinc-400">
          {functions[0].source_file}
        </span>
        <span className="text-zinc-600 ml-2">
          ({functions.length} function{functions.length !== 1 ? 's' : ''})
        </span>
      </div>

      <div className="flex-1 overflow-auto">
        <table className="w-full text-xs font-mono">
          <thead className="sticky top-0 bg-zinc-900 border-b border-zinc-800">
            <tr className="text-zinc-500 text-left">
              <th className="px-3 py-1.5 font-normal">Function</th>
              <th className="px-3 py-1.5 font-normal w-16 text-center">Hit</th>
              <th className="px-3 py-1.5 font-normal w-20 text-right">Exec</th>
              <th className="px-3 py-1.5 font-normal w-24 text-right">Regions</th>
              <th className="px-3 py-1.5 font-normal w-16 text-right">Line</th>
              <th className="px-3 py-1.5 font-normal w-20 text-right">BBs</th>
              <th className="px-3 py-1.5 font-normal w-10"></th>
            </tr>
          </thead>
          <tbody>
            {functions.map((f) => {
              const isActive = f.name === selectedName;
              const isExternal = !f.source_file;
              const url = coverageUrl(f.source_dir, f.source_file, f.line_start, reportBaseUrl);
              return (
                <tr
                  key={f.name}
                  onClick={() => onFunctionClick?.(f)}
                  className={`border-b border-zinc-800/50 cursor-pointer ${isActive ? 'bg-zinc-700/40' : 'hover:bg-zinc-800/40'
                    }`}
                >
                  <td className="px-3 py-1 truncate max-w-xs">
                    <span className={isActive ? 'text-white' : 'text-zinc-300'}>
                      {f.name}
                    </span>
                  </td>
                  <td className="px-3 py-1 text-center">
                    <span
                      className={`inline-block w-2 h-2 rounded-full ${isExternal ? 'bg-zinc-500' : f.coverage.hit ? 'bg-green-500' : 'bg-red-500'
                        }`}
                      title={isExternal ? 'External (no coverage data)' : undefined}
                    />
                  </td>
                  <td className="px-3 py-1 text-right text-zinc-400">
                    {isExternal ? '-' : f.coverage.count.toLocaleString()}
                  </td>
                  <td className="px-3 py-1 text-right text-zinc-400">
                    {isExternal ? '-' : `${f.coverage.regions_covered}/${f.coverage.regions_total}`}
                  </td>
                  <td className="px-3 py-1 text-right text-zinc-500">
                    {f.line_start || '-'}
                  </td>
                  <td className="px-3 py-1 text-right text-zinc-500">
                    {f.bb_count || '-'}
                  </td>
                  <td className="px-3 py-1 text-right">
                    {url && (
                      <a
                        href={url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-blue-400 hover:text-blue-300"
                        title="View in coverage report"
                        onClick={(e) => e.stopPropagation()}
                      >
                        {'->'}
                      </a>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
