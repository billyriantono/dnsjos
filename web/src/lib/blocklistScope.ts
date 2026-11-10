/** Builds target one scope, so the combined All profiles view is not a valid target. */
export function canStartBlocklistBuild(profileId: string | undefined): boolean {
  return profileId !== undefined
}
