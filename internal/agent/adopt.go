package agent

import (
	"bufio"
	"cmp"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// Adoption of a live dnsdist_ootb server (SPEC §17).
const (
	OOTBConfig = DnsdistDir + "/dnsdist.yml"
	OOTBCDB    = DnsdistDir + "/db/blacklist.db"
)

// parseOOTB reads the scalar mapping keys of a dnsdist_ootb YAML file as dotted paths
// ("admin.web.password"). Everything under a list item (the rules) is skipped: only the
// known node-specific keys are needed, so this is not a general YAML parser.
func parseOOTB(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	type level struct {
		indent int
		key    string
	}
	var stack []level
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimRight(sc.Text(), " \t\r")
		body := strings.TrimLeft(line, " ")
		if body == "" || body[0] == '#' {
			continue
		}
		indent := len(line) - len(body)
		for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
			stack = stack[:len(stack)-1]
		}
		if strings.HasPrefix(body, "- ") || body == "-" {
			stack = append(stack, level{indent, "-"})
			continue
		}
		k, v, ok := strings.Cut(body, ":")
		if !ok || (v != "" && v[0] != ' ') {
			return nil, fmt.Errorf("%s:%d: unsupported YAML", path, n)
		}
		stack = append(stack, level{indent, strings.TrimSpace(k)})
		if v = strings.TrimSpace(v); v == "" {
			continue
		}
		keys := make([]string, len(stack))
		for i, l := range stack {
			if l.key == "-" {
				keys = nil
				break
			}
			keys[i] = l.key
		}
		if keys != nil {
			out[strings.Join(keys, ".")] = yamlScalar(v)
		}
	}
	return out, sc.Err()
}

// yamlScalar unquotes a single- or double-quoted scalar and strips a trailing comment.
func yamlScalar(v string) string {
	switch v[0] {
	case '\'':
		if i := strings.LastIndexByte(v, '\''); i > 0 {
			return strings.ReplaceAll(v[1:i], "''", "'")
		}
	case '"':
		if i := strings.LastIndexByte(v, '"'); i > 0 {
			return strings.NewReplacer(`\"`, `"`, `\\`, `\`).Replace(v[1:i])
		}
	}
	if i := strings.Index(v, " #"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	return v
}

// adoption is what `enroll --adopt` takes over from the old config.
type adoption struct {
	Secrets   Secrets
	Overrides map[string]any // JSON merge patch over the profile spec
}

// adoptOOTB extracts the secrets and the node-specific settings (listen addresses, web
// listener + ACL, DoH/DoT certificates, DoH path) from a dnsdist_ootb config. ACL, upstreams and
// blocking come from the profile.
func adoptOOTB(path string) (adoption, error) {
	y, err := parseOOTB(path)
	if err != nil {
		return adoption{}, err
	}
	a := adoption{
		Secrets: Secrets{ConsoleKey: y["admin.console.key"], WebPassword: y["admin.web.password"], WebAPIKey: y["admin.web.apikey"]},
	}
	listen := func(svc, defPort string) []string {
		port, err := strconv.ParseUint(cmp.Or(y["services."+svc+".port"], defPort), 10, 16)
		if err != nil {
			return nil
		}
		var out []string
		for _, ip := range []string{y["services."+svc+".ip4"], y["services."+svc+".ip6"]} {
			if a, err := netip.ParseAddr(strings.Trim(ip, "[]")); err == nil {
				out = append(out, netip.AddrPortFrom(a, uint16(port)).String())
			}
		}
		return out
	}
	lst := map[string]any{}
	if addrs := listen("dns", "53"); len(addrs) > 0 {
		lst["do53"] = map[string]any{"addresses": addrs}
	}
	var cert, key string
	for _, svc := range []string{"doh", "dot"} {
		addrs := listen(svc, map[string]string{"doh": "443", "dot": "853"}[svc])
		o := map[string]any{"enabled": len(addrs) > 0}
		if len(addrs) > 0 {
			o["addresses"] = addrs
			cert, key = y["services."+svc+".cert"], y["services."+svc+".key"]
		}
		if p := y["services."+svc+".path"]; svc == "doh" && p != "" {
			o["path"] = p
		}
		lst[svc] = o
	}
	if cert != "" && key != "" {
		lst["tls"] = map[string]any{"cert_file": cert, "key_file": key}
	}
	a.Overrides = map[string]any{"listen": lst}
	if ap, err := netip.ParseAddrPort(y["admin.web.ip4"] + ":" + y["admin.web.port"]); err == nil {
		web := map[string]any{"listen": ap.String()}
		if acl := splitList(y["admin.web.acl"]); len(acl) > 0 {
			web["prometheus_acl"] = acl
		}
		a.Overrides["webserver"] = web
	}
	return a, nil
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}
