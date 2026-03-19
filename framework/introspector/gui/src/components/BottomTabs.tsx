import type { ReactNode } from 'react';
import { useState } from 'react';

type TabId = 'functions' | 'stats';

interface Tab {
  id: TabId;
  label: string;
}

const TABS: Tab[] = [
  { id: 'functions', label: 'Functions' },
  { id: 'stats', label: 'Stats' },
];

interface Props {
  functionsPanel: ReactNode;
  statsPanel: ReactNode;
}

export function BottomTabs({ functionsPanel, statsPanel }: Props) {
  const [activeTab, setActiveTab] = useState<TabId>('functions');

  return (
    <div className="h-full flex flex-col bg-zinc-900">
      <div className="flex border-b border-zinc-800 flex-shrink-0">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-3 py-1.5 text-xs cursor-pointer transition-colors ${activeTab === tab.id
                ? 'text-zinc-200 border-b-2 border-zinc-400'
                : 'text-zinc-500 hover:text-zinc-300'
              }`}
          >
            {tab.label}
          </button>
        ))}
      </div>
      <div className="flex-1 min-h-0">
        {activeTab === 'functions' ? functionsPanel : statsPanel}
      </div>
    </div>
  );
}
