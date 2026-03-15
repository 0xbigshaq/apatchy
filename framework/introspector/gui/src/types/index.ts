export interface CallTreeNode {
  name: string;
  site_file: string;
  site_line: number;
  site_col: number;
  site_count: number;
  children: CallTreeNode[];
}

export interface FunctionCoverage {
  hit: boolean;
  count: number;
  regions_total: number;
  regions_covered: number;
}

export interface FunctionMeta {
  bb_count: number;
  instruction_count: number;
  line_start: number;
  source_dir: string;
  source_file: string;
  coverage: FunctionCoverage;
}

export interface CallEdge {
  caller: string;
  callee: string;
  is_indirect: boolean;
  site_file: string;
  site_line: number;
  site_col: number;
}

export interface IntrospectMetadata {
  entry_points: string[];
}

export interface IntrospectData {
  metadata: IntrospectMetadata;
  functions: Record<string, FunctionMeta>;
  call_tree: CallTreeNode[];
  call_edges: CallEdge[];
}
