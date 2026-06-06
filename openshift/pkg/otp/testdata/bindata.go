package testdata

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

//go:embed all:networking
var embeddedFS embed.FS

var (
	extractOnce sync.Once
	extractDir  string
)

func FixturePath(elem ...string) string {
	extractOnce.Do(func() {
		dir, err := os.MkdirTemp("", "otp-testdata-")
		if err != nil {
			panic(err)
		}
		if err := fs.WalkDir(embeddedFS, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			target := filepath.Join(dir, path)
			if d.IsDir() {
				return os.MkdirAll(target, 0755)
			}
			data, err := embeddedFS.ReadFile(path)
			if err != nil {
				return err
			}
			return os.WriteFile(target, data, 0644)
		}); err != nil {
			panic(err)
		}
		extractDir = dir
	})
	return filepath.Join(append([]string{extractDir}, elem...)...)
}
