package apply

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// snapshot writes dir as a .tar.gz (modes, owners and mtimes kept) to dst, skipping
// the agent's staging dir and temp files.
func snapshot(dir, dst string) (err error) {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(dst+".tmp", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(dst + ".tmp")
		}
	}()
	zw := gzip.NewWriter(f)
	tw := tar.NewWriter(zw)
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if rel == StagingName || strings.HasSuffix(rel, ".dnsjos-tmp") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		link := ""
		if fi.Mode()&fs.ModeSymlink != 0 {
			if link, err = os.Readlink(p); err != nil {
				return err
			}
		}
		h, err := tar.FileInfoHeader(fi, link)
		if err != nil {
			return err
		}
		h.Name, h.Uname, h.Gname = filepath.ToSlash(rel), "", ""
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if fi.Mode().IsRegular() {
			src, err := os.Open(p)
			if err != nil {
				return err
			}
			_, err = io.Copy(tw, src)
			src.Close()
			return err
		}
		return nil
	})
	for _, c := range []io.Closer{tw, zw} {
		if err == nil {
			err = c.Close()
		}
	}
	if err == nil {
		err = f.Sync()
	}
	if err == nil {
		err = f.Close()
	}
	if err == nil {
		err = os.Rename(dst+".tmp", dst)
	}
	return err
}

// restoreSnapshot makes dir exactly the tree in the snapshot: every entry is written
// back and anything not in it is removed.
func restoreSnapshot(dir, src string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	keep := map[string]bool{".": true}
	type stamp struct {
		p string
		t time.Time
	}
	var dirs []stamp // directory mtimes are set last, after their contents changed
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		rel := filepath.FromSlash(h.Name)
		if !filepath.IsLocal(rel) && rel != "." {
			return fmt.Errorf("snapshot: bad entry %q", h.Name)
		}
		keep[rel] = true
		p := filepath.Join(dir, rel)
		mode := h.FileInfo().Mode()
		switch h.Typeflag {
		case tar.TypeDir:
			if fi, err := os.Lstat(p); err == nil && !fi.IsDir() {
				os.RemoveAll(p)
			}
			if err := os.MkdirAll(p, 0o755); err != nil {
				return err
			}
			dirs = append(dirs, stamp{p, h.ModTime})
		case tar.TypeSymlink:
			os.RemoveAll(p)
			if err := os.Symlink(h.Linkname, p); err != nil {
				return err
			}
		case tar.TypeReg:
			fi, err := os.Lstat(p)
			if err == nil && !fi.Mode().IsRegular() {
				os.RemoveAll(p)
			}
			// Files the apply never touched (the CDB under db/, …) are not rewritten: a
			// rollback must not need free space for the whole tree. The managed files are
			// always rewritten.
			if err == nil && fi.Mode().IsRegular() && !slices.Contains(Managed, rel) && fi.Size() == h.Size &&
				fi.Mode().Perm() == mode.Perm() && fi.ModTime().Round(time.Second).Equal(h.ModTime.Round(time.Second)) {
				break
			}
			b, err := io.ReadAll(tr)
			if err != nil {
				return err
			}
			if err := writeFile(p, b, mode.Perm(), -1); err != nil {
				return err
			}
			os.Chtimes(p, h.ModTime, h.ModTime)
		default:
			continue
		}
		os.Lchown(p, h.Uid, h.Gid) // best effort: only root can (test mode is not root)
		if h.Typeflag != tar.TypeSymlink {
			os.Chmod(p, mode.Perm())
		}
	}
	var extra []string
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if rel, _ := filepath.Rel(dir, p); err == nil && !keep[rel] {
			extra = append(extra, p)
			if d.IsDir() {
				return filepath.SkipDir
			}
		}
		return nil
	})
	for _, p := range extra {
		if err := os.RemoveAll(p); err != nil {
			return err
		}
	}
	for _, d := range slices.Backward(dirs) {
		os.Chtimes(d.p, d.t, d.t)
	}
	return nil
}
