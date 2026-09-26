package configs_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/billyriantono/dnsjos/internal/panel/app"
	"github.com/billyriantono/dnsjos/internal/panel/configs"
	"github.com/billyriantono/dnsjos/internal/panel/db/dbtest"
	"github.com/billyriantono/dnsjos/internal/shared/api"
	"github.com/billyriantono/dnsjos/internal/shared/dnsconf"
)

type client struct {
	t     *testing.T
	url   string
	token string
}

func (c client) expect(want int, method, path string, body, out any) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.url+path, rd)
	req.AddCookie(&http.Cookie{Name: app.SessionCookie, Value: c.token})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		c.t.Fatalf("%s %s: status %d, want %d: %s", method, path, resp.StatusCode, want, b)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			c.t.Fatalf("%s %s: %v: %s", method, path, err, b)
		}
	}
}

func TestConfigs(t *testing.T) {
	pool := dbtest.New(t, "configs")
	ctx := context.Background()
	d := &app.Deps{Pool: pool, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	r := app.NewRouter(d)
	configs.Register(r, d)
	ts := httptest.NewServer(r)
	defer ts.Close()

	login := func(email, role string) client {
		tok := app.NewToken()
		var id string
		if err := pool.QueryRow(ctx, "INSERT INTO users (email, password_hash, role) VALUES ($1, 'x', $2) RETURNING id", email, role).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, "INSERT INTO sessions (id_hash, user_id, expires_at) VALUES ($1, $2, now() + interval '1 hour')", app.HashToken(tok), id); err != nil {
			t.Fatal(err)
		}
		return client{t, ts.URL, tok}
	}
	admin, viewer := login("admin@example.com", "admin"), login("viewer@example.com", "viewer")

	// profiles CRUD
	name, desc := "edge", "edge nodes"
	var p api.Profile
	admin.expect(201, "POST", "/api/v1/profiles", api.ProfileRequest{Name: &name, Description: &desc}, &p)
	admin.expect(409, "POST", "/api/v1/profiles", api.ProfileRequest{Name: &name}, nil)
	admin.expect(400, "POST", "/api/v1/profiles", api.ProfileRequest{}, nil)
	viewer.expect(403, "POST", "/api/v1/profiles", api.ProfileRequest{Name: &desc}, nil)
	newName := "edge-2"
	admin.expect(200, "PATCH", "/api/v1/profiles/"+p.ID, api.ProfileRequest{Name: &newName}, &p)
	// A new profile starts with published version 1 = DefaultConfigSpec.
	if p.Name != "edge-2" || p.Description != "edge nodes" || p.LatestVersion != 1 || p.PublishedVersion == nil || *p.PublishedVersion != 1 {
		t.Fatalf("patched profile: %+v", p)
	}
	var profiles api.List[api.Profile]
	viewer.expect(200, "GET", "/api/v1/profiles", nil, &profiles)
	if profiles.Total != 2 { // + seeded "default"
		t.Fatalf("profiles: %+v", profiles)
	}
	viewer.expect(404, "GET", "/api/v1/profiles/not-a-uuid", nil, nil)

	// versions
	spec := api.DefaultConfigSpec()
	var v1, v2 api.ConfigVersion
	admin.expect(201, "POST", "/api/v1/profiles/"+p.ID+"/versions", api.VersionCreate{Spec: spec, Comment: "first"}, &v1)
	bad := spec
	bad.Upstreams.Servers = nil
	admin.expect(422, "POST", "/api/v1/profiles/"+p.ID+"/versions", api.VersionCreate{Spec: bad}, nil)
	spec2 := api.DefaultConfigSpec()
	spec2.Upstreams.Servers[0].Weight = 50
	spec2.ACL = append(spec2.ACL, "198.51.100.0/24")
	spec2.Abuse.Enabled = false
	admin.expect(201, "POST", "/api/v1/profiles/"+p.ID+"/versions", api.VersionCreate{Spec: spec2}, &v2)
	if v1.Version != 2 || v2.Version != 3 || v1.Published || v1.CreatedBy == nil {
		t.Fatalf("versions: %+v %+v", v1, v2)
	}
	viewer.expect(403, "POST", "/api/v1/profiles/"+p.ID+"/versions/2/publish", nil, nil)
	admin.expect(200, "POST", "/api/v1/profiles/"+p.ID+"/versions/2/publish", nil, &v1)
	admin.expect(404, "POST", "/api/v1/profiles/"+p.ID+"/versions/9/publish", nil, nil)
	if !v1.Published || v1.PublishedAt == nil {
		t.Fatalf("publish: %+v", v1)
	}
	var vl api.List[api.ConfigVersion]
	viewer.expect(200, "GET", "/api/v1/profiles/"+p.ID+"/versions", nil, &vl)
	if vl.Total != 3 || vl.Items[0].Version != 3 {
		t.Fatalf("version list: %+v", vl)
	}
	viewer.expect(200, "GET", "/api/v1/profiles/"+p.ID+"/versions/3", nil, &v2)
	if v2.Spec.Upstreams.Servers[0].Weight != 50 {
		t.Fatalf("v2 spec: %+v", v2.Spec.Upstreams)
	}
	viewer.expect(404, "GET", "/api/v1/profiles/"+p.ID+"/versions/x", nil, nil)
	viewer.expect(200, "GET", "/api/v1/profiles/"+p.ID, nil, &p)
	if p.LatestVersion != 3 || p.PublishedVersion == nil || *p.PublishedVersion != 2 {
		t.Fatalf("profile versions: %+v", p)
	}

	// diff
	var diff api.ConfigVersionDiff
	viewer.expect(200, "GET", "/api/v1/profiles/"+p.ID+"/versions/2/diff/3", nil, &diff)
	got := map[string]string{}
	for _, c := range diff.Changes {
		got[c.Path] = c.Op
	}
	want := map[string]string{"abuse.enabled": "replace", fmt.Sprintf("acl[%d]", len(api.DefaultConfigSpec().ACL)): "add", "upstreams.servers[0].weight": "replace"}
	if len(got) != len(want) || diff.A.Version != 2 || diff.B.Version != 3 {
		t.Fatalf("diff: %+v", diff.Changes)
	}
	for k, op := range want {
		if got[k] != op {
			t.Fatalf("diff %s: %q, want %q (%+v)", k, got[k], op, diff.Changes)
		}
	}

	// preview (masked)
	var rc api.RenderedConfig
	viewer.expect(200, "POST", "/api/v1/profiles/"+p.ID+"/preview", api.PreviewRequest{Spec: spec}, &rc)
	if conf := rc.Files[dnsconf.FileConf]; !strings.Contains(conf, "setKey("+dnsconf.Mask+")") || rc.Files[dnsconf.FileCGK] == "" {
		t.Fatalf("preview: %s", conf)
	}
	viewer.expect(422, "POST", "/api/v1/profiles/"+p.ID+"/preview", api.PreviewRequest{Spec: bad}, nil)

	// node rendered config: published v2 + overrides
	var nodeID string
	if err := pool.QueryRow(ctx, `INSERT INTO nodes (name, hostname, profile_id, overrides)
		VALUES ('n1', 'dns9.example', $1, '{"cgk": {"enabled": false}, "upstreams": {"policy": "roundrobin"}}') RETURNING id`, p.ID).Scan(&nodeID); err != nil {
		t.Fatal(err)
	}
	rc = api.RenderedConfig{}
	viewer.expect(200, "GET", "/api/v1/nodes/"+nodeID+"/config/rendered", nil, &rc)
	if rc.Spec.CGK.Enabled || rc.Spec.Upstreams.Policy != "roundrobin" || !rc.Spec.Abuse.Enabled {
		t.Fatalf("effective spec: %+v", rc.Spec)
	}
	if _, ok := rc.Files[dnsconf.FileCGK]; ok || !strings.Contains(rc.Files[dnsconf.FileBlocking], `"dns9.example"`) {
		t.Fatalf("rendered files: %v", rc.Files)
	}
	pool.Exec(ctx, `UPDATE nodes SET overrides = '{"upstreams": {"policy": "nope"}}' WHERE id = $1`, nodeID)
	viewer.expect(422, "GET", "/api/v1/nodes/"+nodeID+"/config/rendered", nil, nil)
	pool.Exec(ctx, `UPDATE nodes SET profile_id = NULL WHERE id = $1`, nodeID)
	viewer.expect(404, "GET", "/api/v1/nodes/"+nodeID+"/config/rendered", nil, nil)
	viewer.expect(404, "GET", "/api/v1/nodes/00000000-0000-0000-0000-000000000000/config/rendered", nil, nil)

	// copy_from: version 1 of the new profile is the source's newest published spec
	admin.expect(200, "POST", "/api/v1/profiles/"+p.ID+"/versions/3/publish", nil, nil)
	copyName, bogus := "edge-copy", "00000000-0000-0000-0000-000000000000"
	var cp api.Profile
	admin.expect(201, "POST", "/api/v1/profiles", api.ProfileRequest{Name: &copyName, CopyFrom: &p.ID}, &cp)
	var cv api.ConfigVersion
	viewer.expect(200, "GET", "/api/v1/profiles/"+cp.ID+"/versions/1", nil, &cv)
	if !cv.Published || cv.Spec.Abuse.Enabled || cv.Spec.Upstreams.Servers[0].Weight != 50 {
		t.Fatalf("copied version: %+v", cv)
	}
	admin.expect(400, "POST", "/api/v1/profiles", api.ProfileRequest{Name: &desc, CopyFrom: &bogus}, nil)

	// delete: blocked while a node uses the profile
	pool.Exec(ctx, `UPDATE nodes SET profile_id = $2 WHERE id = $1`, nodeID, p.ID)
	admin.expect(409, "DELETE", "/api/v1/profiles/"+p.ID, nil, nil)
	pool.Exec(ctx, `UPDATE nodes SET deleted_at = now() WHERE id = $1`, nodeID)
	viewer.expect(403, "DELETE", "/api/v1/profiles/"+p.ID, nil, nil)
	admin.expect(204, "DELETE", "/api/v1/profiles/"+p.ID, nil, nil)
	admin.expect(404, "DELETE", "/api/v1/profiles/"+p.ID, nil, nil)

	var actions []string
	rows, _ := pool.Query(ctx, "SELECT action FROM audit_log ORDER BY id")
	for rows.Next() {
		var a string
		rows.Scan(&a)
		actions = append(actions, a)
	}
	if strings.Join(actions, ",") != "profile.create,profile.update,config_version.create,config_version.create,config_version.publish,config_version.publish,profile.create,profile.delete" {
		t.Fatalf("audit: %v", actions)
	}
}
