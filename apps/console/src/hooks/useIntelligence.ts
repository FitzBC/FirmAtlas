import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { intelligenceApi } from '../api/client'
import type {
  IntelligenceFilters,
  IntelligenceStatistics,
  Overview,
  SyncRun,
  VulnerabilityPage,
} from '../types'
import { useDebouncedValue } from './useDebouncedValue'

const emptyPage: VulnerabilityPage = {
  items: [], total: 0, limit: 50, offset: 0, page: 1, pages: 0,
  has_previous: false, has_next: false,
}

export function useIntelligence(filters: IntelligenceFilters) {
  const [overview, setOverview] = useState<Overview | null>(null)
  const [page, setPage] = useState<VulnerabilityPage>(emptyPage)
  const [latestSync, setLatestSync] = useState<SyncRun | null>(null)
  const [statistics, setStatistics] = useState<IntelligenceStatistics | null>(null)
  const [loading, setLoading] = useState(true)
  const [filtering, setFiltering] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [pageRefreshKey, setPageRefreshKey] = useState(0)
  const [currentPage, setCurrentPage] = useState(1)
  const requestSequence = useRef(0)
  const previousFilterKey = useRef('')
  const debouncedQuery = useDebouncedValue(filters.query)
  const stableFilters = useMemo(
    () => ({ ...filters, query: debouncedQuery }),
    [debouncedQuery, filters.exploitOnly, filters.kevOnly, filters.relevance, filters.severity, filters.vendor],
  )
  const filterKey = useMemo(() => JSON.stringify(stableFilters), [stableFilters])

  const loadDashboard = useCallback(async () => {
    setError(null)
    try {
      const [overviewResult, syncResult, statisticsResult] = await Promise.all([
        intelligenceApi.overview(),
        intelligenceApi.latestSync(),
        intelligenceApi.statistics(),
      ])
      setOverview(overviewResult)
      setLatestSync(syncResult)
      setStatistics(statisticsResult)
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : '无法连接情报服务')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadDashboard()
  }, [loadDashboard])

  useEffect(() => {
    const filtersChanged = previousFilterKey.current !== filterKey
    previousFilterKey.current = filterKey
    if (filtersChanged && currentPage !== 1) {
      setCurrentPage(1)
      return
    }
    const controller = new AbortController()
    const sequence = ++requestSequence.current
    setFiltering(true)
    setError(null)
    void intelligenceApi.vulnerabilities(stableFilters, currentPage, controller.signal)
      .then((result) => {
        if (sequence === requestSequence.current) setPage(result)
      })
      .catch((caught: unknown) => {
        if (caught instanceof DOMException && caught.name === 'AbortError') return
        if (sequence === requestSequence.current) {
          setError(caught instanceof Error ? caught.message : '筛选请求失败')
        }
      })
      .finally(() => {
        if (sequence === requestSequence.current) setFiltering(false)
      })
    return () => controller.abort()
  }, [stableFilters, filterKey, currentPage, pageRefreshKey])

  useEffect(() => {
    if (latestSync?.status !== 'running') return
    const timer = window.setInterval(() => {
      void intelligenceApi.latestSync().then((result) => {
        setLatestSync(result)
        if (result?.status !== 'running') {
          void loadDashboard()
          setPageRefreshKey((value) => value + 1)
        }
      }).catch(() => undefined)
    }, 1800)
    return () => window.clearInterval(timer)
  }, [latestSync?.status, loadDashboard])

  const refresh = useCallback(async () => {
    await loadDashboard()
    setPageRefreshKey((value) => value + 1)
  }, [loadDashboard])

  return {
    overview, statistics, page, latestSync, loading, filtering, error, refresh,
    currentPage, setCurrentPage,
  }
}
