package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// spaFileServer serves the built dashboard from root. Any path that doesn't map
// to a real file falls back to index.html so client-side routes (e.g. the tab
// views) resolve. API routes are registered as more-specific patterns on the
// mux, so they take precedence over this catch-all.
func spaFileServer(root string) http.HandlerFunc {
	root = filepath.Clean(root)
	index := filepath.Join(root, "index.html")

	return func(w http.ResponseWriter, r *http.Request) {
		p := filepath.Join(root, filepath.Clean("/"+r.URL.Path))

		// Defense in depth against path traversal escaping root.
		if p != root && !strings.HasPrefix(p, root+string(os.PathSeparator)) {
			http.NotFound(w, r)
			return
		}

		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			http.ServeFile(w, r, p)
			return
		}
		http.ServeFile(w, r, index)
	}
}
