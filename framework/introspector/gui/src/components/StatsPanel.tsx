import type { ChartOptions } from 'chart.js';
import {
  ArcElement,
  CategoryScale,
  Chart as ChartJS,
  Filler,
  Legend,
  LinearScale,
  LineController,
  LineElement,
  PieController,
  PointElement,
  TimeScale,
  Tooltip,
} from 'chart.js';
import 'chartjs-adapter-date-fns';
import zoomPlugin from 'chartjs-plugin-zoom';
import { useMemo, useRef, useState } from 'react';
import { Line, Pie } from 'react-chartjs-2';
import type { FuzzerSession } from '../types/stats';

const crosshairPlugin = {
  id: 'crosshair',
  afterDraw(chart: any) {
    if (chart.config.type !== 'line') return;
    const tooltip = chart.tooltip;
    if (!tooltip || !tooltip.opacity) return;
    const ctx = chart.ctx;
    const x = tooltip.caretX;
    const top = chart.scales.y?.top ?? chart.chartArea.top;
    const bottom = chart.scales.y?.bottom ?? chart.chartArea.bottom;
    ctx.save();
    ctx.beginPath();
    ctx.moveTo(x, top);
    ctx.lineTo(x, bottom);
    ctx.lineWidth = 1;
    ctx.strokeStyle = 'rgba(161,161,170,0.4)';
    ctx.stroke();
    ctx.restore();
  },
};

ChartJS.register(
  LineElement,
  PointElement,
  LineController,
  ArcElement,
  PieController,
  CategoryScale,
  LinearScale,
  TimeScale,
  Filler,
  Legend,
  Tooltip,
  zoomPlugin,
  crosshairPlugin,
);

interface Props {
  sessions: FuzzerSession[];
}

const COLORS = {
  edges: '#22c55e',
  features: '#a855f7',
  execS: '#3b82f6',
  corpus: '#a855f7',
  event: '#facc15',
  crash: '#ef4444',
  grid: '#27272a',
  axis: '#71717a',
};

const PIE_COLORS = [
  '#22c55e', '#3b82f6', '#a855f7', '#ef4444', '#facc15',
  '#f97316', '#06b6d4', '#ec4899', '#14b8a6', '#8b5cf6',
  '#f59e0b', '#6366f1', '#10b981', '#e11d48', '#0ea5e9',
];

function formatNumber(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
  if (n >= 1_000) return (n / 1_000).toFixed(1) + 'k';
  return n.toString();
}

export function StatsPanel({ sessions }: Props) {
  const [selectedIdx, setSelectedIdx] = useState(sessions.length - 1);
  const session = sessions[selectedIdx];
  const covChartRef = useRef<ChartJS<'line'>>(null);
  const perfChartRef = useRef<ChartJS<'line'>>(null);

  const { pulsePoints, eventPoints, crashPoints } = useMemo(() => {
    if (!session) return { pulsePoints: [], eventPoints: [], crashPoints: [] };

    const pulses = session.pulses.map((p) => ({
      ts: new Date(p.time).getTime(),
      edges: p.edges,
      features: p.features,
      corpus: p.corpus,
      exec_s: p.exec_s,
    }));

    const interpolate = (evTs: number) => {
      let beforeIdx = 0;
      for (let i = 0; i < pulses.length; i++) {
        if (pulses[i].ts <= evTs) beforeIdx = i;
        else break;
      }
      const before = pulses[beforeIdx];
      const after = pulses[Math.min(beforeIdx + 1, pulses.length - 1)];
      const range = after.ts - before.ts;
      const t = range > 0 ? (evTs - before.ts) / range : 0;
      return Math.round(before.edges + (after.edges - before.edges) * t);
    };

    const funcEvents: { ts: number; edges: number; label: string }[] = [];
    const crashes: { ts: number; edges: number; label: string }[] = [];

    for (const ev of session.events) {
      const evTs = new Date(ev.time).getTime();
      const edges = interpolate(evTs);
      const point = { ts: evTs, edges, label: ev.value };
      if (ev.type === 'crash') {
        crashes.push(point);
      } else {
        funcEvents.push(point);
      }
    }

    return { pulsePoints: pulses, eventPoints: funcEvents, crashPoints: crashes };
  }, [session]);

  const mutatorData = useMemo(() => {
    if (!session || !session.mutators) return [];
    return Object.entries(session.mutators)
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count);
  }, [session]);

  const xMin = pulsePoints.length ? pulsePoints[0].ts : 0;
  const xMax = pulsePoints.length ? pulsePoints[pulsePoints.length - 1].ts : 1;

  const zoomPanOptions = useMemo(() => ({
    limits: {
      x: { min: xMin, max: xMax, minRange: 1000 },
    },
    zoom: {
      wheel: { enabled: true },
      pinch: { enabled: true },
      mode: 'x' as const,
    },
    pan: {
      enabled: true,
      mode: 'x' as const,
    },
  }), [xMin, xMax]);

  const resetZoom = () => {
    covChartRef.current?.resetZoom();
    perfChartRef.current?.resetZoom();
  };

  const coverageData = useMemo(() => ({
    datasets: [
      {
        label: 'edges',
        data: pulsePoints.map((p) => ({ x: p.ts, y: p.edges })),
        borderColor: COLORS.edges,
        backgroundColor: COLORS.edges,
        borderWidth: 2,
        pointRadius: 0,
        pointHitRadius: 6,
        tension: 0.2,
        yAxisID: 'y',
      },
      {
        label: 'features',
        data: pulsePoints.map((p) => ({ x: p.ts, y: p.features })),
        borderColor: COLORS.features,
        backgroundColor: COLORS.features,
        borderWidth: 2,
        pointRadius: 0,
        pointHitRadius: 6,
        tension: 0.2,
        yAxisID: 'y1',
      },
      {
        label: 'new function',
        data: eventPoints.map((e) => ({ x: e.ts, y: e.edges })),
        borderColor: COLORS.event,
        backgroundColor: COLORS.event,
        borderWidth: 0,
        pointRadius: 5,
        pointHoverRadius: 7,
        pointStyle: 'circle',
        showLine: false,
        yAxisID: 'y',
      },
      {
        label: 'crash',
        data: crashPoints.map((e) => ({ x: e.ts, y: e.edges })),
        borderColor: COLORS.crash,
        backgroundColor: COLORS.crash,
        borderWidth: 0,
        pointRadius: 4,
        pointHoverRadius: 6,
        pointStyle: 'circle',
        showLine: false,
        yAxisID: 'y',
        order: -1,
      },
    ],
  }), [pulsePoints, eventPoints, crashPoints]);

  const coverageOptions: ChartOptions<'line'> = useMemo(() => ({
    responsive: true,
    maintainAspectRatio: false,
    interaction: {
      mode: 'nearest',
      axis: 'x',
      intersect: false,
    },
    scales: {
      x: {
        type: 'time',
        time: { displayFormats: { second: 'HH:mm:ss', minute: 'HH:mm', hour: 'HH:mm' } },
        grid: { color: COLORS.grid },
        ticks: { color: COLORS.axis, font: { size: 10 }, maxTicksLimit: 12 },
      },
      y: {
        position: 'left',
        grid: { color: COLORS.grid },
        ticks: { color: COLORS.edges, font: { size: 10 }, callback: (v) => formatNumber(v as number) },
        grace: '40%',
      },
      y1: {
        position: 'right',
        grid: { drawOnChartArea: false },
        ticks: { color: COLORS.features, font: { size: 10 }, callback: (v) => formatNumber(v as number) },
        grace: '25%',
      },
    },
    plugins: {
      legend: {
        labels: {
          color: '#a1a1aa',
          font: { size: 11 },
          usePointStyle: true,
          generateLabels: (chart) => {
            return chart.data.datasets.map((ds, i) => ({
              text: ds.label ?? '',
              fontColor: '#a1a1aa',
              fillStyle: ds.borderColor as string,
              strokeStyle: ds.borderColor as string,
              lineWidth: (ds as any).showLine === false ? 0 : 2,
              pointStyle: (ds as any).showLine === false ? 'circle' : 'line',
              hidden: !chart.isDatasetVisible(i),
              datasetIndex: i,
            }));
          },
        },
      },
      tooltip: {
        position: 'nearest',
        backgroundColor: '#18181b',
        borderColor: '#3f3f46',
        borderWidth: 1,
        titleColor: '#a1a1aa',
        bodyColor: '#d4d4d8',
        titleFont: { size: 11 },
        bodyFont: { size: 11 },
        usePointStyle: true,
        callbacks: {
          label: (ctx) => {
            if (ctx.dataset.label === 'new function') {
              const ev = eventPoints[ctx.dataIndex];
              return ev ? ev.label : '';
            }
            if (ctx.dataset.label === 'crash') {
              const ev = crashPoints[ctx.dataIndex];
              return ev ? ev.label : '';
            }
            return `${ctx.dataset.label}: ${formatNumber(ctx.parsed.y ?? 0)}`;
          },
        },
      },
      zoom: zoomPanOptions,
    },
  }), [eventPoints, crashPoints, zoomPanOptions]);

  const perfData = useMemo(() => ({
    datasets: [
      {
        label: 'exec/s',
        data: pulsePoints.map((p) => ({ x: p.ts, y: p.exec_s })),
        borderColor: COLORS.execS,
        backgroundColor: COLORS.execS,
        borderWidth: 2,
        pointRadius: 0,
        pointHitRadius: 6,
        tension: 0.2,
        yAxisID: 'y',
      },
      {
        label: 'corpus',
        data: pulsePoints.map((p) => ({ x: p.ts, y: p.corpus })),
        borderColor: COLORS.corpus,
        backgroundColor: COLORS.corpus,
        borderWidth: 2,
        pointRadius: 0,
        pointHitRadius: 6,
        tension: 0.2,
        yAxisID: 'y1',
      },
    ],
  }), [pulsePoints]);

  const perfOptions: ChartOptions<'line'> = useMemo(() => ({
    responsive: true,
    maintainAspectRatio: false,
    interaction: {
      mode: 'nearest',
      axis: 'x',
      intersect: false,
    },
    scales: {
      x: {
        type: 'time',
        time: { displayFormats: { second: 'HH:mm:ss', minute: 'HH:mm', hour: 'HH:mm' } },
        grid: { color: COLORS.grid },
        ticks: { color: COLORS.axis, font: { size: 10 }, maxTicksLimit: 8 },
      },
      y: {
        position: 'left',
        grid: { color: COLORS.grid },
        ticks: { color: COLORS.execS, font: { size: 10 }, callback: (v) => formatNumber(v as number) },
      },
      y1: {
        position: 'right',
        grid: { drawOnChartArea: false },
        ticks: { color: COLORS.corpus, font: { size: 10 }, callback: (v) => formatNumber(v as number) },
      },
    },
    plugins: {
      legend: {
        labels: { color: '#a1a1aa', font: { size: 11 }, usePointStyle: true, pointStyle: 'line' },
      },
      tooltip: {
        backgroundColor: '#18181b',
        borderColor: '#3f3f46',
        borderWidth: 1,
        titleColor: '#a1a1aa',
        bodyColor: '#d4d4d8',
        titleFont: { size: 11 },
        bodyFont: { size: 11 },
      },
      zoom: zoomPanOptions,
    },
  }), [zoomPanOptions]);

  const pieData = useMemo(() => ({
    labels: mutatorData.map((m) => m.name),
    datasets: [{
      data: mutatorData.map((m) => m.count),
      backgroundColor: mutatorData.map((_, i) => PIE_COLORS[i % PIE_COLORS.length]),
      borderColor: '#18181b',
      borderWidth: 1,
    }],
  }), [mutatorData]);

  const pieOptions: ChartOptions<'pie'> = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: '#18181b',
        borderColor: '#3f3f46',
        borderWidth: 1,
        titleColor: '#a1a1aa',
        bodyColor: '#d4d4d8',
        titleFont: { size: 11 },
        bodyFont: { size: 11 },
      },
    },
  };

  if (!session || !pulsePoints.length) {
    return (
      <div className="h-full flex items-center justify-center text-zinc-600 text-sm">
        No fuzzing stats available
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col bg-zinc-900 border-t border-zinc-800">
      <div className="flex items-center px-3 py-1.5 border-b border-zinc-800 text-xs flex-shrink-0">
        <span className="text-zinc-500">Stats</span>
        {sessions.length > 1 && (
          <>
            <span className="text-zinc-600 mx-2">|</span>
            <select
              value={selectedIdx}
              onChange={(e) => setSelectedIdx(Number(e.target.value))}
              className="bg-zinc-800 text-zinc-300 text-xs px-1.5 py-0.5 rounded border border-zinc-700"
            >
              {sessions.map((s, i) => (
                <option key={i} value={i}>
                  Session {i + 1} - {s.start_time}
                </option>
              ))}
            </select>
          </>
        )}
        <span className="text-zinc-600 ml-2">
          {session.workers} worker{session.workers !== 1 ? 's' : ''}
        </span>
        <span className="text-zinc-600 mx-1">|</span>
        <span className="text-zinc-600">
          {session.pulses.length} pulse{session.pulses.length !== 1 ? 's' : ''}
        </span>
        <span className="text-zinc-600 mx-1">|</span>
        <span className="text-zinc-600">
          {session.events.length} event{session.events.length !== 1 ? 's' : ''}
        </span>
        <span className="text-zinc-600 mx-1">|</span>
        <button
          onClick={resetZoom}
          className="text-zinc-400 hover:text-zinc-200 px-1.5 py-0.5 rounded bg-zinc-800 border border-zinc-700"
        >
          reset zoom
        </button>
      </div>

      <div className="flex-1 overflow-auto p-2 flex flex-col gap-2 min-h-0">
        <div className="grid grid-cols-2 gap-2">
          {/* Performance chart */}
          <div className="bg-zinc-950 rounded p-2">
            <span className="text-xs text-zinc-500 mb-1 block">Performance</span>
            <div style={{ height: '180px' }}>
              <Line ref={perfChartRef} data={perfData} options={perfOptions} />
            </div>
          </div>

          {/* Mutators pie */}
          <div className="bg-zinc-950 rounded p-2 flex flex-col min-h-[160px]">
            <span className="text-xs text-zinc-500 mb-1">Mutators (NEW inputs)</span>
            {mutatorData.length === 0 ? (
              <div className="flex-1 flex items-center justify-center text-zinc-600 text-xs">
                No mutator data yet
              </div>
            ) : (
              <div className="flex-1 flex">
                <div className="w-1/2">
                  <Pie data={pieData} options={pieOptions} />
                </div>
                <div className="w-1/2 overflow-y-auto text-xs pl-1">
                  {mutatorData.map((m, i) => (
                    <div key={m.name} className="flex items-center gap-1 py-0.5">
                      <span
                        className="inline-block w-2 h-2 rounded-full flex-shrink-0"
                        style={{ backgroundColor: PIE_COLORS[i % PIE_COLORS.length] }}
                      />
                      <span className="text-zinc-400 truncate">{m.name}</span>
                      <span className="text-zinc-500 ml-auto flex-shrink-0">{m.count}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Coverage chart - full width */}
        <div className="bg-zinc-950 rounded p-2">
          <span className="text-xs text-zinc-500 mb-1 block">Coverage (scroll to zoom, drag to pan)</span>
          <div style={{ height: '220px' }}>
            <Line ref={covChartRef} data={coverageData} options={coverageOptions} />
          </div>
        </div>
      </div>
    </div>
  );
}
