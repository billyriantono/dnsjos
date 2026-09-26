import { keepPreviousData, useQuery } from '@tanstack/react-query'

import { api, qk } from './client'

export const RANGES = { '1h': 3600, '6h': 6 * 3600, '24h': 24 * 3600, '7d': 7 * 86400 } as const
export type Range = keyof typeof RANGES

/**
 * Node metrics for a sliding window ending now. `from` is computed inside the queryFn so the
 * key stays stable per range and each 60 s refetch slides the window forward.
 */
export const useNodeRangeMetrics = (id: string, range: Range) =>
  useQuery({
    queryKey: [...qk.node(id), 'metrics', 'range', range],
    queryFn: () => api.nodes.metrics(id, { from: new Date(Date.now() - RANGES[range] * 1000).toISOString() }),
    refetchInterval: 60_000,
    placeholderData: keepPreviousData,
  })
