package api

// SpecChange is one entry of the structured diff between two specs.
type SpecChange struct {
	Path string `json:"path"` // e.g. "upstreams.servers[0].weight"; "" = whole spec
	Op   string `json:"op"`   // add | remove | replace
	Old  any    `json:"old"`  // null for add
	New  any    `json:"new"`  // null for remove
}

// ConfigVersionDiff is GET /profiles/{id}/versions/{a}/diff/{b}: both versions plus
// the changes that turn a into b.
type ConfigVersionDiff struct {
	VersionDiff
	Changes []SpecChange `json:"changes"`
}
