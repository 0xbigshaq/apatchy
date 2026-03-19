export interface FuzzerPulse {
  time: string;
  edges: number;
  features: number;
  corpus: number;
  corpus_size: string;
  total_execs: number;
  exec_s: number;
  worker_exec_s: number | null;
  rss: string;
  crashes: number;
}

export interface FuzzerEvent {
  type: string;
  time: string;
  value: string;
}

export interface FuzzerSession {
  start_time: string;
  workers: number;
  pulses: FuzzerPulse[];
  events: FuzzerEvent[];
  mutators: Record<string, number>;
}
