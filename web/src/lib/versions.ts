/**
 * Nodes always run the newest published version, so publishing an older one changes nothing.
 * Rolling back therefore means copying the old spec into a new version and publishing that.
 */
export const needsRollForward = (version: number, liveVersion: number | null) => liveVersion !== null && version < liveVersion

export const rollbackComment = (version: number, liveVersion: number) => `Rollback to v${version} (from v${liveVersion})`
