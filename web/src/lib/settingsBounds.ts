import type { Settings } from './api/types.ts'

/** Mirrors validateSettings in internal/panel/server/settings.go (settingsBounds.test.ts checks they match). */
export const SETTINGS_BOUNDS: Record<Exclude<keyof Settings, 'public_url'>, { min: number; max: number }> = {
  blocklist_build_interval_minutes: { min: 15, max: 7 * 24 * 60 },
  metrics_retention_days: { min: 1, max: 3650 },
  blocked_retention_days: { min: 1, max: 3650 },
  analytics_retention_days: { min: 1, max: 3650 },
  agent_poll_interval_s: { min: 5, max: 3600 },
  agent_heartbeat_interval_s: { min: 5, max: 600 },
}
