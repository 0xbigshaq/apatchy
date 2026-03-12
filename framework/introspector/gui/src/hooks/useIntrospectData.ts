import { useState, useEffect } from 'react';
import type { IntrospectData } from '../types';

export function useIntrospectData() {
  const [data, setData] = useState<IntrospectData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('./introspect.json')
      .then((res) => {
        if (!res.ok) throw new Error(`Failed to load introspect.json: ${res.status}`);
        return res.json();
      })
      .then((json) => setData(json as IntrospectData))
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  return { data, error, loading };
}
