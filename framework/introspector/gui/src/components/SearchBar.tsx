interface Props {
  query: string;
  onChange: (query: string) => void;
  matchCount: number;
}

export function SearchBar({ query, onChange, matchCount }: Props) {
  return (
    <div className="flex items-center gap-2 px-2 py-1.5 border-b border-zinc-800">
      <input
        type="text"
        value={query}
        onChange={(e) => onChange(e.target.value)}
        placeholder="Search..."
        className="bg-zinc-800 text-zinc-200 text-xs rounded px-2 py-1 w-full border border-zinc-700 focus:border-zinc-500 focus:outline-none placeholder-zinc-500 font-mono"
      />
      {query && (
        <span className="text-xs text-zinc-600 flex-shrink-0">
          {matchCount}
        </span>
      )}
    </div>
  );
}
