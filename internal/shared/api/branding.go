package api

// Branding is the public GET /api/v1/branding: the panel's runtime brand (SPEC §15).
// Assets holds every BrandingAssets key, each "/branding/<file>?v=<mtime>" or null when
// the operator has not provided that file.
type Branding struct {
	Name    string             `json:"name"`
	Tagline string             `json:"tagline"`
	Assets  map[string]*string `json:"assets"`
}

// BrandingAssets maps Branding.Assets keys to the candidate files in DNSJOS_BRAND_DIR
// (first present wins). GET /branding/{file} serves only BrandingFiles.
var BrandingAssets = map[string][]string{
	"login_logo":      {"login-logo.png"},
	"navbar_light":    {"navbar-light.png"},
	"navbar_dark":     {"navbar-dark.png"},
	"login_bg":        {"login-bg.webp", "login-bg.jpg"},
	"login_bg_mobile": {"login-bg-mobile.webp", "login-bg-mobile.jpg"},
	"cloud":           {"cloud.webp"},
	"favicon_ico":     {"favicon.ico"},
	"icon_192":        {"icon-192.png"},
	"icon_512":        {"icon-512.png"},
	"apple_touch":     {"apple-touch-icon.png"},
}

// BrandingFiles is the allowlist of GET /branding/{file}: file name → Content-Type.
var BrandingFiles = map[string]string{
	"login-logo.png":       "image/png",
	"navbar-light.png":     "image/png",
	"navbar-dark.png":      "image/png",
	"login-bg.webp":        "image/webp",
	"login-bg.jpg":         "image/jpeg",
	"login-bg-mobile.webp": "image/webp",
	"login-bg-mobile.jpg":  "image/jpeg",
	"cloud.webp":           "image/webp",
	"cloud-mirrored.webp":  "image/webp",
	"favicon.ico":          "image/x-icon",
	"icon-16.png":          "image/png",
	"icon-32.png":          "image/png",
	"icon-48.png":          "image/png",
	"icon-192.png":         "image/png",
	"icon-512.png":         "image/png",
	"apple-touch-icon.png": "image/png",
}
