package server

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/billyriantono/dnsjos/internal/panel/app"
	"github.com/billyriantono/dnsjos/internal/panel/httpx"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

// brand serves the runtime branding (SPEC §15): name/tagline from the environment, image
// files dropped by the operator into dir. Files are looked up per request, so adding or
// replacing one needs no restart; their URLs carry ?v=<mtime> and are cached for a day.
type brand struct{ name, tagline, dir string }

func registerBranding(r *app.Router, cfg brand) {
	r.Public("GET /api/v1/branding", cfg.info)
	r.Public("GET /branding/{file...}", func(w http.ResponseWriter, req *http.Request) {
		if !cfg.serve(w, req, req.PathValue("file"), "public, max-age=86400") {
			httpx.NotFound(w)
		}
	})
	r.Public("GET /favicon.ico", func(w http.ResponseWriter, req *http.Request) {
		// Unversioned URL: short cache so a newly added brand favicon shows up soon.
		if !cfg.serve(w, req, "favicon.ico", "public, max-age=3600") {
			w.Header().Set("Content-Type", "image/x-icon")
			w.Header().Set("Cache-Control", "public, max-age=3600")
			w.Write(defaultFavicon)
		}
	})
	r.Public("GET /manifest.webmanifest", cfg.manifest)
}

// open returns an allowlisted, regular brand file. The allowlist is exact file names, so
// no request path can leave dir.
func (b brand) open(name string) (*os.File, os.FileInfo, bool) {
	if _, ok := api.BrandingFiles[name]; !ok {
		return nil, nil, false
	}
	f, err := os.Open(filepath.Join(b.dir, name))
	if err != nil {
		return nil, nil, false
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		f.Close()
		return nil, nil, false
	}
	return f, st, true
}

func (b brand) serve(w http.ResponseWriter, r *http.Request, name, cache string) bool {
	f, st, ok := b.open(name)
	if !ok {
		return false
	}
	defer f.Close()
	w.Header().Set("Content-Type", api.BrandingFiles[name])
	w.Header().Set("Cache-Control", cache)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, name, st.ModTime(), f)
	return true
}

// url is the versioned URL of the first present file, or nil.
func (b brand) url(files ...string) *string {
	for _, name := range files {
		if f, st, ok := b.open(name); ok {
			f.Close()
			u := "/branding/" + name + "?v=" + strconv.FormatInt(st.ModTime().Unix(), 10)
			return &u
		}
	}
	return nil
}

func (b brand) info(w http.ResponseWriter, _ *http.Request) {
	out := api.Branding{Name: b.name, Tagline: b.tagline, Assets: map[string]*string{}}
	for key, files := range api.BrandingAssets {
		out.Assets[key] = b.url(files...)
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (b brand) manifest(w http.ResponseWriter, _ *http.Request) {
	type icon struct {
		Src   string `json:"src"`
		Sizes string `json:"sizes"`
		Type  string `json:"type"`
	}
	icons := []icon{}
	for _, i := range []struct{ file, sizes string }{{"icon-192.png", "192x192"}, {"icon-512.png", "512x512"}} {
		if u := b.url(i.file); u != nil {
			icons = append(icons, icon{*u, i.sizes, "image/png"})
		}
	}
	if len(icons) == 0 {
		icons = append(icons, icon{"/favicon.ico", "32x32", "image/x-icon"})
	}
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Type", "application/manifest+json")
	json.NewEncoder(w).Encode(map[string]any{"name": b.name, "short_name": b.name, "start_url": "/",
		"display": "standalone", "icons": icons})
}

// defaultFavicon is a neutral 32x32 slate disc (PNG inside an ICO), generated so the
// repository ships no image asset.
var defaultFavicon = func() []byte {
	img := image.NewNRGBA(image.Rect(0, 0, 32, 32))
	for y := range 32 {
		for x := range 32 {
			if dx, dy := x*2-31, y*2-31; dx*dx+dy*dy <= 30*30 {
				img.Set(x, y, color.NRGBA{0x64, 0x74, 0x8b, 0xff})
			}
		}
	}
	var p bytes.Buffer
	png.Encode(&p, img)
	var ico bytes.Buffer
	binary.Write(&ico, binary.LittleEndian, struct {
		Reserved, Type, Count   uint16
		W, H, Colors, Reserved2 uint8
		Planes, BPP             uint16
		Size, Offset            uint32
	}{0, 1, 1, 32, 32, 0, 0, 1, 32, uint32(p.Len()), 22})
	ico.Write(p.Bytes())
	return ico.Bytes()
}()
