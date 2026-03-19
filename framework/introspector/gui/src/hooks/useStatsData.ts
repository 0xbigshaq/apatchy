import { useEffect, useState } from 'react';
import type { FuzzerSession } from '../types/stats';

export function useStatsData() {
  const [sessions, setSessions] = useState<FuzzerSession[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('./stat.json')
      .then((res) => {
        if (!res.ok) throw new Error(`Failed to load stat.json: ${res.status}`);
        return res.json();
      })
      .then((json) => {
        if (Array.isArray(json)) {
          setSessions(json as FuzzerSession[]);
        }
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  return { sessions, error, loading };
}
